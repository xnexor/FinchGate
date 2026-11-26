use super::*;

struct Fixture(PathBuf);

impl Fixture {
    fn new(parent: &Path) -> Self {
        let path = parent.join(format!("muse-ntfs-qa-{}", crate::core::token::generate()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
#[ignore = "requires the running Everything Service and writable fixture directories on the fixed NTFS drives"]
async fn official_ntfs_reuses_one_index_and_tracks_changes() {
    assert!(service_running());
    let binaries = PathBuf::from(std::env::var_os("MUSE_CONNECTOR_EVERYTHING_QA").unwrap());
    let fixture_dirs = std::env::var_os("MUSE_CONNECTOR_NTFS_QA_DIRS").unwrap();
    let fixtures: Vec<_> = std::env::split_paths(&fixture_dirs)
        .map(|parent| Fixture::new(&parent))
        .collect();
    let roots: Vec<_> = crate::core::access::fixed_local_roots()
        .into_values()
        .filter(|path| ntfs_volume(path).is_some())
        .collect();
    assert!(roots.len() >= 2);
    assert_eq!(fixtures.len(), roots.len());
    let fixture_root = |fixture: &Fixture| {
        roots
            .iter()
            .find(|root| fixture.0.starts_with(root))
            .expect("fixture must belong to a tested disk")
    };
    for root in &roots {
        assert_eq!(
            fixtures
                .iter()
                .filter(|fixture| fixture_root(fixture) == root)
                .count(),
            1
        );
    }

    let needle = format!("MuseNtfs{}", std::process::id());
    let filename = format!("{needle}.txt");
    for fixture in &fixtures {
        std::fs::write(fixture.0.join(&filename), "isolated fixture").unwrap();
    }
    let index = Fixture::new(&std::env::temp_dir());
    let cancel = AtomicBool::new(false);
    let query = |engine: &Everything, scope: &[PathBuf], name: &str| {
        let mut state = engine.processes.lock().unwrap();
        engine
            .query_ntfs(
                &mut state,
                scope,
                &roots,
                name,
                &cancel,
                Instant::now() + QUERY_BUDGET,
            )
            .expect("volume indexing fell back before completing")
    };
    let wait_for =
        |engine: &Everything, scope: &[PathBuf], name: &str, count: usize, budget: Duration| {
            let start = Instant::now();
            loop {
                let result = query(engine, scope, name);
                assert_eq!(result.ntfs_roots, roots);
                if result.covered && result.paths.len() == count {
                    break start.elapsed();
                }
                assert!(
                    start.elapsed() < budget,
                    "expected {count} hits for {name}; got {} (indexing={})",
                    result.paths.len(),
                    result.scanning
                );
                std::thread::sleep(Duration::from_millis(75));
            }
        };
    let engine = Everything::new(binaries.clone(), index.0.clone(), true).unwrap();
    let cold = wait_for(
        &engine,
        &roots,
        &needle,
        fixtures.len(),
        Duration::from_secs(175),
    );
    let full = query(&engine, &roots, &needle);
    for fixture in &fixtures {
        assert!(full.paths.contains(&fixture.0.join(&filename)));
    }
    let instance = engine
        .processes
        .lock()
        .unwrap()
        .ntfs
        .as_ref()
        .unwrap()
        .name
        .clone();
    for fixture in &fixtures {
        let single = query(
            &engine,
            std::slice::from_ref(fixture_root(fixture)),
            &needle,
        );
        assert!(single.covered);
        assert_eq!(single.paths, [fixture.0.join(&filename)]);
    }
    assert_eq!(
        engine.processes.lock().unwrap().ntfs.as_ref().unwrap().name,
        instance
    );

    let samples = |scope: &[PathBuf], hits| {
        let mut values: Vec<_> = (0..30)
            .map(|_| {
                wait_for(&engine, scope, &needle, hits, Duration::from_secs(10)).as_secs_f64()
                    * 1000.0
            })
            .collect();
        values.sort_by(f64::total_cmp);
        (values[14], values[28])
    };
    let one = std::slice::from_ref(fixture_root(fixtures.last().unwrap()));
    let (single_p50, single_p95) = samples(one, 1);
    let (all_p50, all_p95) = samples(&roots, fixtures.len());

    let changed = fixtures
        .last()
        .unwrap()
        .0
        .join(format!("Renamed{needle}.txt"));
    std::fs::rename(fixtures.last().unwrap().0.join(&filename), &changed).unwrap();
    let rename = wait_for(
        &engine,
        one,
        &format!("Renamed{needle}"),
        1,
        Duration::from_secs(15),
    );
    std::fs::remove_file(changed).unwrap();
    let delete = wait_for(&engine, one, &needle, 0, Duration::from_secs(15));
    engine.stop_managed();
    let db = index.0.join("ntfs-v1/Everything.db");
    let bytes = std::fs::metadata(&db).unwrap().len();
    assert!(bytes > 0);

    let offline_name = format!("Offline{needle}");
    std::fs::write(
        fixtures
            .last()
            .unwrap()
            .0
            .join(format!("{offline_name}.txt")),
        "offline change",
    )
    .unwrap();
    let reopened = Everything::new(binaries, index.0.clone(), true).unwrap();
    let reload = wait_for(&reopened, one, &offline_name, 1, Duration::from_secs(90));
    println!(
        "NTFS drives={} cold_s={:.3} single_p50_ms={single_p50:.2} single_p95_ms={single_p95:.2} all_p50_ms={all_p50:.2} all_p95_ms={all_p95:.2} rename_ms={:.1} delete_ms={:.1} reload_s={:.3} db_mib={:.2}",
        roots.len(),
        cold.as_secs_f64(),
        rename.as_secs_f64() * 1000.0,
        delete.as_secs_f64() * 1000.0,
        reload.as_secs_f64(),
        bytes as f64 / (1024.0 * 1024.0)
    );
    verify_agent_search(reopened, &index.0, &needle, roots.len()).await;
}

async fn verify_agent_search(engine: Everything, home: &Path, needle: &str, expected: usize) {
    use crate::core::access::{AccessPolicy, GrantScope, ScopeMode};
    use crate::core::access_runtime::AccessRuntime;
    use crate::core::api::{ApiOptions, ApiState, BridgePaths, serve_listener};
    use crate::core::config::BridgeConfig;
    use crate::profile::{ProfileKind, RuntimeProfile};

    let profile = RuntimeProfile {
        kind: ProfileKind::Production,
        home: home.join("isolated-profile"),
        onboarding_qa: false,
    };
    std::fs::create_dir(&profile.home).unwrap();
    let access = AccessRuntime::with_test_engine(&profile, engine);
    access
        .save(
            AccessPolicy {
                mode: ScopeMode::Full,
                search: GrantScope::AllLocal,
                ..AccessPolicy::default()
            },
            false,
        )
        .unwrap();
    access.issue_agent_token(|_| {}).unwrap();
    let token = access.agent_token().unwrap();
    let (state, _events) = ApiState::new(
        BridgeConfig::default(),
        crate::core::token::generate(),
        BridgePaths {
            config: profile.home.join("config.json"),
            token: profile.home.join("token"),
            audit: profile.home.join("audit.log"),
        },
        ApiOptions::default(),
    );
    state.attach_access(access.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let authority = listener.local_addr().unwrap();
    let (shutdown, signal) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(serve_listener(state, listener, signal));
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let endpoint = format!("http://{authority}/agent/v1/search");
    let response = client
        .post(&endpoint)
        .json(&serde_json::json!({"name":needle}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let request = if let Some(target) = std::env::var_os("MUSE_CONNECTOR_NTFS_QA_TARGET") {
        let target = PathBuf::from(target);
        assert!(target.is_file());
        serde_json::json!({"name": target.file_name().unwrap().to_str().unwrap(), "root":"drive-e"})
    } else {
        serde_json::json!({"name": needle})
    };

    let mut ready = false;
    let start = Instant::now();
    let mut timings = Vec::new();
    while timings.len() < 30 {
        let attempt = Instant::now();
        let response = client
            .post(&endpoint)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let response: serde_json::Value = response.json().await.unwrap();
        assert_eq!(response["backend"], "everything_ntfs");
        if response["complete"] == true {
            let hits = response["hits"].as_array().unwrap();
            if request.get("root").is_some() {
                let target =
                    PathBuf::from(std::env::var_os("MUSE_CONNECTOR_NTFS_QA_TARGET").unwrap());
                let relative = target
                    .strip_prefix(r"E:\")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/");
                assert!(hits.iter().any(|hit| hit["path"] == relative));
            } else {
                assert_eq!(hits.len(), expected);
            }
            if ready {
                timings.push(attempt.elapsed().as_secs_f64() * 1000.0);
            }
            ready = true;
        } else {
            assert!(start.elapsed() < Duration::from_secs(90));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
    assert_eq!(
        client
            .get(format!(
                "http://{authority}/agent/v1/read?root=drive-e&path=sample.txt"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    timings.sort_by(f64::total_cmp);
    println!(
        "NTFS authenticated_loopback_p50_ms={:.2} authenticated_loopback_p95_ms={:.2}",
        timings[14], timings[28]
    );
    shutdown.send(true).unwrap();
    server.await.unwrap().unwrap();
    access.stop_search_engine();
}
