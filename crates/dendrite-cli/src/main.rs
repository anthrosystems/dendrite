use dendrite_cli::{Command, render};

fn main() {
    let argument = std::env::args().nth(1);
    let command = Command::parse(argument.as_deref());
    println!("{}", render(command));
}
