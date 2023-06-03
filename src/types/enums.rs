#[derive(Clone)]
pub enum LogLevel {
    Trace = 10,
    Debug = 20,
    Info = 30,
    Warning = 40,
    Error = 50,
    Fatal = 60,
}

pub enum BufferValue<'a> {
    Buffer(&'a [u8]),
    Number(usize),
    String(String)
}