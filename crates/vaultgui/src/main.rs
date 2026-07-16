slint::include_modules!();

mod autolock;

fn main() -> Result<(), slint::PlatformError> {
    let app = App::new()?;
    app.run()
}
