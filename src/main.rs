use std::{ env};

use sol_grep::{InputParsed, full_content_readed};






fn main() {
    let user_input: Vec<String> = env::args().collect();

    let parsed_input: InputParsed<'_> = match InputParsed::new(&user_input) {
        Ok(config) => config,

        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

 full_content_readed(parsed_input);
}

