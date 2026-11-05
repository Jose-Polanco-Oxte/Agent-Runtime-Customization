use std::path::Path;

use arc::manifest::loader::parse_yaml_with_guarded_stack;
use arc::{ArcManifest, load_project};

#[test]
fn shipped_projects_load_and_manifest_round_trips_preserve_semantics() {
    for example in [
        "01-fintech-payments",
        "02-healthcare-api",
        "03-production-infrastructure",
        "04-monorepo-release",
        "05-ml-data-pipeline",
        "06-incident-response",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(example)
            .join("arc.yaml");
        let project = load_project(&path).unwrap_or_else(|error| panic!("{example}: {error:#}"));
        if let Some(aliases) = &project.aliases {
            let catalog = arc::catalog::load_aliases(project.workdir.join("aliases.yaml"))
                .expect("standalone alias catalog");
            assert_eq!(&catalog, aliases, "{example}: alias loaders must agree");
        }
        let original = arc::load_manifest(&path).expect("manifest");
        let encoded = yaml_serde::to_string(&original).expect("serialize manifest");
        let decoded: ArcManifest =
            parse_yaml_with_guarded_stack(encoded, example).expect("round trip manifest");
        // Declaration indices are loader metadata and intentionally not serialized.
        assert_eq!(
            serde_json::to_value(&original).unwrap(),
            serde_json::to_value(&decoded).unwrap(),
            "{example}"
        );
        assert!(!project.guards.lifecycle.is_empty() || !project.guards.tools.is_empty());
    }
}

#[test]
fn anchors_unicode_block_scalars_and_quoted_values_keep_their_meaning() {
    let manifest: ArcManifest = parse_yaml_with_guarded_stack(
        "schema: '1.0'\nroot: {workdir: '.'}\nskills:\n  first: &skill\n    src: 'yes'\n    description: |-\n      Revisión: código # literal\n      segunda línea 🦀\n  second: *skill\n"
            .into(),
        "scalar compatibility",
    )
    .expect("anchors and multiline text");
    let skills = manifest.skills.as_ref().expect("skills");
    assert_eq!(skills["first"], skills["second"]);
    let arc::manifest::schema::SkillDeclaration::Single(item) = &skills["first"] else {
        panic!("expected leaf skill");
    };
    assert_eq!(item.src, Path::new("yes"));
    assert_eq!(
        item.description,
        "Revisión: código # literal\nsegunda línea 🦀"
    );
    let serialized = yaml_serde::to_string(&manifest).expect("serialize special scalars");
    let decoded: ArcManifest = parse_yaml_with_guarded_stack(serialized, "scalars").unwrap();
    assert_eq!(manifest, decoded);
}

#[test]
fn invalid_yaml_and_ambiguous_documents_fail_with_typed_errors() {
    for content in [
        "schema: '1.0'\nroot: [\n",
        "schema: '1.0'\nschema: '2.0'\nroot: {workdir: '.'}\n",
        "schema: '1.0'\nroot: {workdir: '.'}\nunknown: true\n",
        "schema: '1.0'\nroot: {workdir: '.'}\n---\nschema: '1.0'\nroot: {workdir: '.'}\n",
        "schema: '1.0'\nroot: *undefined\n",
    ] {
        let error = parse_yaml_with_guarded_stack::<ArcManifest>(content.into(), "invalid fixture")
            .expect_err("invalid input must fail closed");
        assert!(
            error.downcast_ref::<yaml_serde::Error>().is_some(),
            "{error:#}"
        );
        assert!(format!("{error:#}").contains("invalid fixture"));
    }
}
