#[derive(Clone, Default)]
pub struct AppHandle;

pub trait Emitter {
    fn emit<S: serde::Serialize>(&self, _event: &str, _payload: S) -> Result<(), ()> { Ok(()) }
}
impl Emitter for AppHandle {}
