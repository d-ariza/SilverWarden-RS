use thiserror::Error;

#[derive(Error, Debug)]
pub enum AutotypeError {
    #[error("Autotype failed: {0}")]
    Failed(String),
}

pub trait Autotyper {
    fn type_text(&self, text: &str) -> Result<(), AutotypeError>;
}
