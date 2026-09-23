fn main() -> std::io::Result<()> {
    let schema = "../../schemas/protobuf/mailent/observation/v1/observation.proto";
    println!("cargo:rerun-if-changed={schema}");
    prost_build::compile_protos(&[schema], &["../../schemas/protobuf"])
}
