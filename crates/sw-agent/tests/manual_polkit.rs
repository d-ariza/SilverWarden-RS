use sw_systemauth::biometrics::{Biometrics, BiometricsError, PolkitBiometrics};
use sw_systemauth::CallingContext;

#[tokio::test]
#[ignore]
async fn test_polkit_biometrics_smoke() {
    let ctx = CallingContext {
        process_pid: std::process::id(),
        ..CallingContext::default()
    };
    let b = PolkitBiometrics::new();
    let res = b.authenticate("SilverWarden test", &ctx).await;
    match res {
        Ok(auth) => eprintln!("Polkit OK: authorized={auth}"),
        Err(BiometricsError::ServiceUnavailable(e)) => {
            eprintln!("Polkit no disponible (esperado en CI): {e}");
        }
        Err(BiometricsError::Failed(e)) => {
            eprintln!("Polkit call falló: {e}");
        }
        Err(e) => panic!("Error inesperado: {e}"),
    }
}
