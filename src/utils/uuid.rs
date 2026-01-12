// UUID утилиты

pub fn generate_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn is_valid(uuid_str: &str) -> bool {
    uuid::Uuid::parse_str(uuid_str).is_ok()
}
