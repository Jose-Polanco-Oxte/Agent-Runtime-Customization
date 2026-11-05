use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::schema::{
    AliasesManifest, ArcManifest, GuardsConfig, GuardsModule, RoleConfig, RolesModule,
    RulesManifest, SkillDeclaration, SkillsModule,
};

/// Fully loaded Arc project representation after discovering and parsing all manifests, modules, and convention files.
#[derive(Debug, Clone)]
pub struct LoadedArcProject {
    pub manifest_path: PathBuf,
    pub manifest: ArcManifest,
    pub workdir: PathBuf,
    pub instructions_path: Option<PathBuf>,
    pub instructions_content: Option<String>,
    pub skills: BTreeMap<String, SkillDeclaration>,
    pub roles: BTreeMap<String, RoleConfig>,
    /// Role source snapshots read and validated during project loading. The
    /// compiler must consume these bytes instead of reopening the path later.
    pub role_sources: BTreeMap<String, RoleSource>,
    pub guards: GuardsConfig,
    pub rules: Option<RulesManifest>,
    pub aliases: Option<AliasesManifest>,
}

#[derive(Debug, Clone)]
pub struct RoleSource {
    pub path: PathBuf,
    pub content: String,
}

use std::collections::HashSet;

/// Validates and returns an explicitly selected Arc manifest file.
///
/// Unlike [`discover_arc_root`], this does not treat directories as search
/// roots and never walks parent directories.
pub fn resolve_explicit_manifest_file<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path = path.as_ref();
    inspect_all_components_without_indirection(path, "explicit manifest")?;
    let metadata = inspect_path_without_indirection(path)
        .with_context(|| format!("Failed to inspect explicit Arc manifest path {:?}", path))?;

    if !metadata.is_file() {
        bail!(
            "Explicit Arc manifest path is not a regular file: {:?}",
            path
        );
    }

    Ok(path.to_path_buf())
}

/// Discovers the nearest `arc.yaml` manifest by checking `start_dir` and walking up its ancestor directories (M7).
pub fn discover_arc_root<P: AsRef<Path>>(start_dir: P) -> Result<PathBuf> {
    let start = start_dir.as_ref();

    // Explicit file path handling
    if start.file_name().map_or(false, |n| {
        n == "arc.yaml"
            || n.to_string_lossy().ends_with(".yaml")
            || n.to_string_lossy().ends_with(".yml")
    }) {
        if start.exists() {
            inspect_all_components_without_indirection(start, "explicit manifest")?;
            let meta = inspect_path_without_indirection(start)?;
            if meta.is_file() {
                return Ok(start.to_path_buf());
            }
        } else {
            bail!(
                "No 'arc.yaml' found: explicit manifest file not found at {:?}",
                start
            );
        }
    }

    let start_meta = match fs::symlink_metadata(start) {
        Ok(_) => inspect_path_without_indirection(start)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "No 'arc.yaml' found in {:?} or any of its parent directories: path does not exist",
                start
            );
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed inspecting manifest discovery path {:?}", start));
        }
    };
    if start_meta.is_file() {
        return Ok(start.to_path_buf());
    }

    if !start_meta.is_dir() {
        bail!(
            "Manifest discovery start path is not a directory: {:?}",
            start
        );
    }

    if !start.exists() {
        bail!(
            "No 'arc.yaml' found in {:?} or any of its parent directories: path does not exist",
            start
        );
    }

    let mut visited = HashSet::new();
    let mut curr = start.to_path_buf();

    loop {
        inspect_all_components_without_indirection(&curr, "manifest discovery directory")?;
        let current_meta = inspect_path_without_indirection(&curr)?;
        if !current_meta.is_dir() {
            break;
        }
        if let Ok(canonical) = curr.canonicalize() {
            if !visited.insert(canonical) {
                break;
            }
        }

        let candidate = curr.join("arc.yaml");
        if candidate.exists() {
            inspect_all_components_without_indirection(&candidate, "discovered manifest")?;
            let meta = inspect_path_without_indirection(&candidate)?;
            if meta.is_file() {
                return Ok(candidate);
            }
        }

        match curr.parent() {
            Some(parent) if parent != curr => {
                curr = parent.to_path_buf();
            }
            _ => break,
        }
    }

    bail!(
        "No 'arc.yaml' found in {:?} or any of its parent directories",
        start
    )
}

use std::fs::File;
use std::io::Read;

fn metadata_is_indirected(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn inspect_path_without_indirection(path: &Path) -> Result<fs::Metadata> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("Failed inspecting path {:?}", path))?;
    if metadata_is_indirected(&metadata) {
        bail!(
            "Refusing symlink or reparse point in manifest discovery: {:?}",
            path
        );
    }
    Ok(metadata)
}

/// Checks every existing component of a path without resolving links. A
/// canonicalized final path is not sufficient: a linked ancestor can redirect
/// an apparently contained resource to a different tree between checks.
pub(crate) fn inspect_all_components_without_indirection(
    path: &Path,
    resource_name: &str,
) -> Result<()> {
    let normalized_path = normalize_handle_path(path.to_path_buf());
    let mut current = PathBuf::new();
    for component in normalized_path.components() {
        if component == std::path::Component::CurDir {
            continue;
        }
        if component == std::path::Component::ParentDir {
            bail!(
                "Refusing parent traversal while inspecting {resource_name}: {normalized_path:?}"
            );
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata_is_indirected(&metadata) {
                    bail!(
                        "Refusing symlink or reparse point in {resource_name}: {:?}",
                        current
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "Missing path component while inspecting {resource_name}: {:?}",
                    current
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed inspecting {resource_name} path component {:?}",
                        current
                    )
                });
            }
        }
    }
    Ok(())
}

/// Loads and validates the root `ArcManifest` from a specific file path (M5).
pub fn load_manifest<P: AsRef<Path>>(path: P) -> Result<ArcManifest> {
    let manifest_path = path.as_ref();

    let mut file = File::open(manifest_path)
        .with_context(|| format!("Failed to open manifest file at: {:?}", manifest_path))?;
    let opened_path = normalize_handle_path(get_handle_final_path(&file).with_context(|| {
        format!(
            "Failed to identify opened manifest handle at {:?}",
            manifest_path
        )
    })?);
    let expected_path =
        normalize_handle_path(manifest_path.canonicalize().with_context(|| {
            format!("Failed to canonicalize manifest path {:?}", manifest_path)
        })?);
    if opened_path != expected_path {
        bail!(
            "Manifest file changed while opening: expected {:?}, opened {:?}",
            expected_path,
            opened_path
        );
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("Failed to read manifest file at: {:?}", manifest_path))?;

    let manifest: ArcManifest = parse_yaml_with_guarded_stack(content, "manifest")
        .with_context(|| format!("Failed to parse manifest YAML at: {:?}", manifest_path))?;

    if manifest.schema != "1.0" {
        bail!(
            "Unsupported schema version '{}' in {:?}. Expected '1.0'",
            manifest.schema,
            manifest_path
        );
    }

    Ok(manifest)
}

/// Parses manifest-controlled YAML on a guarded worker stack. The parser can
/// recurse while materializing nested YAML before Arc's iterative linking
/// begins; isolating that parser stack converts a malformed deep document into
/// a normal error instead of aborting the hook process. No input-size or
/// expression-depth policy is imposed.
pub fn parse_yaml_with_guarded_stack<T>(content: String, resource_name: &str) -> Result<T>
where
    T: DeserializeOwned + Send + 'static,
{
    let resource_name = resource_name.to_string();
    let handle = std::thread::Builder::new()
        .name("arc-yaml-parser".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(move || yaml_serde::from_str::<T>(&content))
        .with_context(|| format!("Failed starting guarded parser for {resource_name}"))?;
    match handle.join() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => {
            Err(anyhow::Error::new(error)).context(format!("Failed parsing {resource_name} YAML"))
        }
        Err(_) => bail!("YAML parser worker failed while parsing {resource_name}"),
    }
}

#[cfg(windows)]
pub fn get_handle_final_path(file: &std::fs::File) -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;

    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            hFile: *mut std::ffi::c_void,
            lpszFilePath: *mut u16,
            cchFilePath: u32,
            dwFlags: u32,
        ) -> u32;
    }

    const FILE_NAME_NORMALIZED: u32 = 0x0;
    const VOLUME_NAME_DOS: u32 = 0x0;

    let handle = file.as_raw_handle();
    let mut buffer: Vec<u16> = vec![0; 1024];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            handle as *mut std::ffi::c_void,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };

    if len == 0 {
        bail!("GetFinalPathNameByHandleW failed for opened handle");
    }

    if len as usize > buffer.len() {
        buffer.resize(len as usize + 1, 0);
        let len2 = unsafe {
            GetFinalPathNameByHandleW(
                handle as *mut std::ffi::c_void,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if len2 == 0 {
            bail!("GetFinalPathNameByHandleW failed on retry");
        }
    }

    let os_str = OsString::from_wide(&buffer[..len as usize]);
    let mut path_str = os_str.to_string_lossy().to_string();
    if path_str.starts_with(r"\\?\") {
        path_str = path_str[4..].to_string();
    }
    Ok(PathBuf::from(path_str))
}

#[cfg(not(windows))]
pub fn get_handle_final_path(file: &std::fs::File) -> Result<PathBuf> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let fd_path = if cfg!(target_os = "linux") {
            format!("/proc/self/fd/{fd}")
        } else {
            format!("/dev/fd/{fd}")
        };
        if let Ok(target) = std::fs::read_link(fd_path) {
            return Ok(target);
        }
    }
    bail!("Handle path resolution not supported on this platform")
}

pub(crate) fn normalize_handle_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if value.as_bytes().starts_with(&[92, 92, 63, 92]) {
            return PathBuf::from(&value[4..]);
        }
    }
    path
}

/// Opens a file, validates containment and metadata on the open handle, and reads its content without reopening (M5).
pub fn read_contained_file(
    workdir: &Path,
    target: &Path,
    resource_name: &str,
) -> Result<(PathBuf, String)> {
    validate_host_path_syntax(target)?;
    if target
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        bail!(
            "Workspace containment violation: {} path {:?} contains parent traversal",
            resource_name,
            target
        );
    }
    let norm_workdir = workdir
        .canonicalize()
        .with_context(|| format!("Failed canonicalizing workdir {:?}", workdir))?;
    let norm_workdir_path = normalize_handle_path(norm_workdir);
    let normalized_target = normalize_handle_path(target.to_path_buf());
    inspect_all_components_without_indirection(&normalized_target, resource_name)?;
    let expected_target =
        normalize_handle_path(normalized_target.canonicalize().with_context(|| {
            format!("Failed canonicalizing {} path {:?}", resource_name, target)
        })?);

    // Open file descriptor once
    let mut file = File::open(target)
        .with_context(|| format!("Failed opening {} file at {:?}", resource_name, target))?;

    // Query exact kernel path of the opened descriptor handle (M5)
    #[cfg(windows)]
    let canonical_target = {
        let handle_path = get_handle_final_path(&file).with_context(|| {
            format!(
                "Failed querying handle final path for {} at {:?}",
                resource_name, target
            )
        })?;
        let handle_path = normalize_handle_path(handle_path);
        if handle_path != expected_target || !handle_path.starts_with(&norm_workdir_path) {
            bail!(
                "Opened handle for {} at {:?} resolves to {:?}, expected {:?}, within workdir {:?}",
                resource_name,
                target,
                handle_path,
                expected_target,
                workdir
            );
        }
        handle_path
    };

    #[cfg(not(windows))]
    let canonical_target = {
        let canonical = normalize_handle_path(get_handle_final_path(&file).with_context(|| {
            format!(
                "Unable to identify the opened handle for {} at {:?}; refusing fallback path reopening",
                resource_name, target
            )
        })?);
        if canonical != expected_target || !canonical.starts_with(&norm_workdir_path) {
            bail!(
                "Opened handle for {} at {:?} resolves to {:?}, expected {:?}, within workdir {:?}",
                resource_name,
                target,
                canonical,
                expected_target,
                workdir
            );
        }
        canonical
    };

    // Read directly from open descriptor
    let mut content = String::new();
    file.read_to_string(&mut content).with_context(|| {
        format!(
            "Failed reading {} file from open descriptor at {:?}",
            resource_name, target
        )
    })?;

    Ok((canonical_target, content))
}

/// Loads an entire Arc project from the path to `arc.yaml` (M5).
pub fn load_project<P: AsRef<Path>>(manifest_path: P) -> Result<LoadedArcProject> {
    let manifest_path = manifest_path.as_ref().to_path_buf();
    let manifest = load_manifest(&manifest_path)?;

    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    // Resolve workdir: relative paths are resolved relative to the base_dir (or execution dir)
    let workdir = resolve_relative_path(base_dir, &manifest.root.workdir)?;

    if !workdir.exists() {
        bail!(
            "Specified workdir {:?} does not exist (resolved to {:?})",
            manifest.root.workdir,
            workdir
        );
    }

    // Resolve instructions path if present
    let (instructions_path, instructions_content) = if let Some(ref inst) =
        manifest.root.instructions
    {
        let resolved = resolve_relative_path(&workdir, inst)?;
        let (canonical_inst, content) = read_contained_file(&workdir, &resolved, "instructions")?;
        (Some(canonical_inst), Some(content))
    } else {
        (None, None)
    };

    // Initialize collections
    let mut skills = manifest.skills.clone().unwrap_or_default();
    let mut roles = manifest.roles.clone().unwrap_or_default();
    let mut guards = manifest.guards.clone().unwrap_or_default();

    // Process explicitly declared modules
    if let Some(ref modules) = manifest.modules {
        for (section_name, module_rel_path) in modules {
            let module_path = resolve_relative_path(&workdir, module_rel_path)?;
            let (_canonical_module, content) = read_contained_file(
                &workdir,
                &module_path,
                &format!("module '{}'", section_name),
            )?;

            match section_name.as_str() {
                "skills" => {
                    if manifest.skills.is_some() {
                        bail!(
                            "Duplicate section definition: 'skills' is defined both inline and in module {:?}",
                            module_rel_path
                        );
                    }
                    let module: SkillsModule =
                        parse_yaml_with_guarded_stack(content, "skills module").with_context(
                            || format!("Failed to parse skills module YAML at {:?}", module_path),
                        )?;
                    if module.schema != manifest.schema {
                        bail!(
                            "Schema mismatch in module {:?}: expected '{}', found '{}'",
                            module_path,
                            manifest.schema,
                            module.schema
                        );
                    }
                    skills = module.skills;
                }
                "roles" => {
                    if manifest.roles.is_some() {
                        bail!(
                            "Duplicate section definition: 'roles' is defined both inline and in module {:?}",
                            module_rel_path
                        );
                    }
                    let module: RolesModule =
                        parse_yaml_with_guarded_stack(content, "roles module").with_context(
                            || format!("Failed to parse roles module YAML at {:?}", module_path),
                        )?;
                    if module.schema != manifest.schema {
                        bail!(
                            "Schema mismatch in module {:?}: expected '{}', found '{}'",
                            module_path,
                            manifest.schema,
                            module.schema
                        );
                    }
                    roles = module.roles;
                }
                "guards" => {
                    if manifest.guards.is_some() {
                        bail!(
                            "Duplicate section definition: 'guards' is defined both inline and in module {:?}",
                            module_rel_path
                        );
                    }
                    let module: GuardsModule =
                        parse_yaml_with_guarded_stack(content, "guards module").with_context(
                            || format!("Failed to parse guards module YAML at {:?}", module_path),
                        )?;
                    if module.schema != manifest.schema {
                        bail!(
                            "Schema mismatch in module {:?}: expected '{}', found '{}'",
                            module_path,
                            manifest.schema,
                            module.schema
                        );
                    }
                    guards = module.guards;
                }
                other => {
                    bail!(
                        "Unknown module section '{}' in manifest. Supported sections: 'skills', 'roles', 'guards'",
                        other
                    );
                }
            }
        }
    }

    // Load conventional rules.yaml if present in workdir
    let rules_path = workdir.join("rules.yaml");
    let rules = if rules_path.exists() {
        let (_canonical, content) = read_contained_file(&workdir, &rules_path, "rules convention")?;
        let parsed: RulesManifest = parse_yaml_with_guarded_stack(content, "rules convention")
            .with_context(|| format!("Failed parsing rules YAML at {:?}", rules_path))?;
        if parsed.schema != manifest.schema {
            bail!(
                "Schema mismatch in {:?}: expected '{}', found '{}'",
                rules_path,
                manifest.schema,
                parsed.schema
            );
        }
        Some(parsed)
    } else {
        None
    };

    // Load conventional aliases.yaml if present in workdir
    let aliases_path = workdir.join("aliases.yaml");
    let aliases = if aliases_path.exists() {
        let (_canonical, content) =
            read_contained_file(&workdir, &aliases_path, "aliases convention")?;
        let parsed: AliasesManifest = parse_yaml_with_guarded_stack(content, "aliases convention")
            .with_context(|| format!("Failed parsing aliases YAML at {:?}", aliases_path))?;
        if parsed.schema != manifest.schema {
            bail!(
                "Schema mismatch in {:?}: expected '{}', found '{}'",
                aliases_path,
                manifest.schema,
                parsed.schema
            );
        }
        Some(parsed)
    } else {
        None
    };

    // Validate that all skill source directories exist and are contained (M4)
    validate_skills_sources(&workdir, &skills)?;

    let role_sources = load_role_sources(&workdir, &roles)?;

    Ok(LoadedArcProject {
        manifest_path,
        manifest,
        workdir,
        instructions_path,
        instructions_content,
        skills,
        roles,
        role_sources,
        guards,
        rules,
        aliases,
    })
}

fn load_role_sources(
    workdir: &Path,
    roles: &BTreeMap<String, RoleConfig>,
) -> Result<BTreeMap<String, RoleSource>> {
    let mut sources = BTreeMap::new();
    for (role_name, role_config) in roles {
        let Some(relative_source) = role_config.src.as_ref() else {
            continue;
        };
        let raw_source = resolve_relative_path(workdir, relative_source)?;
        let canonical_source = validate_containment(
            workdir,
            &raw_source,
            &format!("Role '{}' source", role_name),
        )?;
        let (path, content) = if canonical_source.is_file() {
            read_contained_file(workdir, &raw_source, &format!("role '{}'", role_name))?
        } else if canonical_source.is_dir() {
            let role_md = canonical_source.join("ROLE.md");
            let readme_md = canonical_source.join("README.md");
            let content_path = if role_md.is_file() {
                role_md
            } else if readme_md.is_file() {
                readme_md
            } else {
                bail!(
                    "Role '{}' path {:?} is a directory, but does not contain 'ROLE.md' or 'README.md'.",
                    role_name,
                    canonical_source
                );
            };
            read_contained_file(
                workdir,
                &content_path,
                &format!("role '{}' content", role_name),
            )?
        } else {
            bail!(
                "Role '{}' declared source path {:?} is not a regular file or directory.",
                role_name,
                canonical_source
            );
        };
        sources.insert(role_name.clone(), RoleSource { path, content });
    }
    Ok(sources)
}

/// Validates that all declared skill sources exist, are valid files/directories, and stay within workdir (M4).
pub fn validate_skills_sources(
    workdir: &Path,
    skills: &BTreeMap<String, SkillDeclaration>,
) -> Result<()> {
    for (skill_name, decl) in skills {
        validate_skill_declaration_source(workdir, skill_name, decl)?;
    }
    Ok(())
}

fn validate_skill_declaration_source(
    workdir: &Path,
    skill_name: &str,
    decl: &SkillDeclaration,
) -> Result<()> {
    match decl {
        SkillDeclaration::Single(item) => {
            let skill_src_path = resolve_relative_path(workdir, &item.src)?;
            if !skill_src_path.exists() {
                bail!(
                    "Skill '{}' source path {:?} does not exist (resolved to {:?})",
                    skill_name,
                    item.src,
                    skill_src_path
                );
            }
            let canonical = validate_containment(
                workdir,
                &skill_src_path,
                &format!("skill '{}' source", skill_name),
            )?;
            let meta = fs::metadata(&canonical).with_context(|| {
                format!(
                    "Failed reading metadata for skill '{}' source at {:?}",
                    skill_name, canonical
                )
            })?;
            if !meta.is_dir() && !meta.is_file() {
                bail!(
                    "Skill '{}' source at {:?} must be a regular directory or file",
                    skill_name,
                    canonical
                );
            }
        }
        SkillDeclaration::Group { members, .. } => {
            for (sub_name, sub_decl) in members {
                let full_name = format!("{}.{}", skill_name, sub_name);
                validate_skill_declaration_source(workdir, &full_name, sub_decl)?;
            }
        }
    }
    Ok(())
}

/// Resolves a manifest path using host semantics and rejects a path written in
/// an incompatible rooted syntax instead of silently treating it as relative
/// (M4).
pub fn resolve_relative_path(base_dir: &Path, target: &Path) -> Result<PathBuf> {
    validate_host_path_syntax(target)?;
    Ok(if target.is_absolute() {
        target.to_path_buf()
    } else {
        base_dir.join(target)
    })
}

/// Validates that a path is contained within the resolved workspace directory and returns canonical path (M5).
pub fn validate_containment(workdir: &Path, target: &Path, resource_name: &str) -> Result<PathBuf> {
    validate_host_path_syntax(target)?;
    if target
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        bail!(
            "Workspace containment violation: {} path {:?} contains parent traversal",
            resource_name,
            target
        );
    }
    inspect_all_components_without_indirection(workdir, "workspace root")?;
    inspect_all_components_without_indirection(target, resource_name)?;
    let norm_workdir = workdir
        .canonicalize()
        .with_context(|| format!("Failed canonicalizing workdir {:?}", workdir))?;
    let norm_target = target
        .canonicalize()
        .with_context(|| format!("Failed canonicalizing {} path {:?}", resource_name, target))?;

    if !norm_target.starts_with(&norm_workdir) {
        bail!(
            "Workspace containment violation: {} path {:?} escapes workdir {:?}",
            resource_name,
            target,
            workdir
        );
    }

    Ok(norm_target)
}

fn validate_host_path_syntax(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::path::Component;

        let has_prefix = path
            .components()
            .any(|component| matches!(component, Component::Prefix(_)));
        let has_root = path
            .components()
            .any(|component| matches!(component, Component::RootDir));
        if has_root && !has_prefix {
            bail!(
                "Manifest path {:?} uses a root-relative syntax without a Windows drive or UNC prefix",
                path
            );
        }
        if has_prefix && !has_root {
            bail!(
                "Manifest path {:?} uses a drive-relative Windows syntax; use a rooted or workspace-relative path",
                path
            );
        }
    }

    #[cfg(unix)]
    {
        let text = path.as_os_str().to_string_lossy();
        let bytes = text.as_bytes();
        let windows_drive_absolute = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\');
        if text.starts_with('\\') || windows_drive_absolute {
            bail!(
                "Manifest path {:?} uses Windows-specific rooted syntax on a Unix host",
                path
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{load_project, parse_yaml_with_guarded_stack, resolve_relative_path};
    use crate::manifest::schema::RuleExpression;

    #[test]
    fn guarded_yaml_parser_handles_deep_rule_expression_without_hook_stack_growth() {
        let mut yaml = String::new();
        for depth in 0..2_000 {
            yaml.push_str(&"  ".repeat(depth));
            yaml.push_str("not:\n");
        }
        yaml.push_str(&"  ".repeat(2_000));
        yaml.push_str("rule: leaf\n");

        let error = parse_yaml_with_guarded_stack::<RuleExpression>(yaml, "deep rule expression")
            .expect_err("deep YAML must be rejected as a parser error, not crash the hook");
        let error_text = format!("{error:#}");
        assert!(
            error_text.contains("recursion") || error_text.contains("nest"),
            "unexpected guarded parser error: {error_text}"
        );

        let mut valid_yaml = String::new();
        for depth in 0..64 {
            valid_yaml.push_str(&"  ".repeat(depth));
            valid_yaml.push_str("not:\n");
        }
        valid_yaml.push_str(&"  ".repeat(64));
        valid_yaml.push_str("rule: leaf\n");
        let expression: RuleExpression =
            parse_yaml_with_guarded_stack(valid_yaml, "valid nested rule expression")
                .expect("guarded parse");
        let mut current = &expression;
        for _ in 0..64 {
            let RuleExpression::Not { not } = current else {
                panic!("expected nested not expression");
            };
            current = not;
        }
        assert!(matches!(current, RuleExpression::RuleRef { rule } if rule == "leaf"));
        std::mem::forget(expression);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_root_relative_and_drive_relative_foreign_paths_on_windows() {
        let base = std::path::Path::new(r"C:\workspace");
        assert!(resolve_relative_path(base, std::path::Path::new(r"\other\file")).is_err());
        assert!(resolve_relative_path(base, std::path::Path::new(r"C:relative\file")).is_err());
        assert!(resolve_relative_path(base, std::path::Path::new(r"C:\workspace\file")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_windows_rooted_paths_on_unix() {
        let base = std::path::Path::new("/workspace");
        assert!(resolve_relative_path(base, std::path::Path::new(r"C:\workspace\file")).is_err());
        assert!(resolve_relative_path(base, std::path::Path::new(r"\\server\share\file")).is_err());
    }

    #[test]
    fn role_sources_are_snapshotted_during_project_load() {
        let root = std::env::temp_dir().join(format!(
            "arc_loader_role_snapshot_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let workdir = root.join("workspace");
        std::fs::create_dir_all(&workdir).expect("workspace directory");
        std::fs::write(
            root.join("arc.yaml"),
            "schema: \"1.0\"\nroot:\n  workdir: workspace\nroles:\n  reviewer:\n    description: Reviewer\n    src: reviewer.md\n",
        )
        .expect("manifest");
        let role = workdir.join("reviewer.md");
        std::fs::write(&role, "original role").expect("role source");

        let project = load_project(root.join("arc.yaml")).expect("project load");
        std::fs::write(&role, "replacement role").expect("replacement");

        assert_eq!(
            project
                .role_sources
                .get("reviewer")
                .expect("role snapshot")
                .content,
            "original role"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
