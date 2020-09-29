static ITEMS: &str = include_str!(concat!(env!("OUT_DIR"), "/items.h"));

fn main() {
    print!("{}", ITEMS);
}
