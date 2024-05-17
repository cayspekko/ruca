use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use openssl::asn1::Asn1Integer;
use openssl::bn::BigNum;
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use openssl::x509::extension::{SubjectKeyIdentifier, SubjectAlternativeName};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
// use openssl::nid::Nid;
use tera::{Tera, Context};
use std::io::{stdin, stdout, Write};
use std::fs;
use std::env;
use serde::{Deserialize, Serialize};



fn new_cert_cli() {
    let mut input = String::new();
    input.clear();

    print!("Enter the filename prefix for the certificate: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).unwrap();
    let name = input.trim().to_string();

    input.clear();
    print!("Enter the subject for the certificate: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).unwrap();
    let common_name = input.trim().to_string();

    input.clear();
    print!("Enter the number of days until the certificate expires: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).unwrap();
    let days = input.trim().parse::<u32>().unwrap();

    input.clear();
    print!("Enter the key size for the certificate: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).unwrap();
    let key_size = input.trim().parse::<u32>().unwrap();

    let cr = CertRequest {
        name: name,
        template: None,
        subject: Some(common_name),
        days: Some(days),
        key: None,
        key_size: Some(key_size),
    };

    let (certificate_pem, private_key_pem) = generate_cert(&cr).unwrap();
    let certificate_pem_string = String::from_utf8(certificate_pem).unwrap();
    let private_key_pem_string = String::from_utf8(private_key_pem).unwrap();
    
    println!("Certificate:\n{}", certificate_pem_string);
    println!("Private Key:\n{}", private_key_pem_string);

}

#[derive(Deserialize)]
struct CertRequest {
    name: String,
    template: Option<String>,
    subject: Option<String>,
    days: Option<u32>,
    key: Option<String>,
    key_size: Option<u32>,
}

impl CertRequest {
    fn validate(&self) -> Result<(), &'static str> {
        match self.key_size {
            Some(1024) | Some(2048) | Some(4096) | Some(8192) => Ok(()),
            _ => Err("Invalid key size. It must be one of 1024, 2048, 4096, or 8192."),
        }
    }
}

#[derive(Serialize)]
struct CertResponse {
    certificate: String,
    private_key: String,
}

async fn generate_cert_endpoint(cert_request: web::Json<CertRequest>) -> impl Responder {
    // populate defaults if not included
    let cert_request = CertRequest {
        name: cert_request.name.clone(),
        template: Some(cert_request.template.clone().unwrap_or("default".to_string())),
        subject: Some(cert_request.subject.clone().unwrap_or(format!("CN={}", cert_request.name))),
        days: Some(cert_request.days.unwrap_or(365)),
        key: cert_request.key.clone(),
        key_size: Some(cert_request.key_size.unwrap_or(2048)),
    };

    match cert_request.validate() {
        Ok(_) => (),
        Err(e) => return HttpResponse::BadRequest().body(e),
    }

    let (certificate_pem, private_key_pem )= generate_cert(&cert_request).unwrap();

    HttpResponse::Ok().json(CertResponse {
        certificate: String::from_utf8(certificate_pem).unwrap(),
        private_key: String::from_utf8(private_key_pem).unwrap(),
    })
}

fn parse_certificate(certificate: &str) -> Result<X509, &'static str> {
    let parsed_certificate = match X509::from_pem(certificate.as_bytes()) {
        Ok(certificate) => certificate,
        Err(_) => return Err("Invalid certificate"),
    };
    // Print the subject, subject alt name, expiry date, and issuer
    println!("Subject: {:?}", parsed_certificate.subject_name());
    println!("Subject Alt Name: {:?}", parsed_certificate.subject_alt_names());
    println!("Expiry Date: {}", parsed_certificate.not_after());
    println!("Issuer: {:?}", parsed_certificate.issuer_name());

    Ok(parsed_certificate)
}

fn generate_cert(cert_request: &CertRequest) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // get or generate the private key
    let pkey = match cert_request.key {
        Some(ref key) => {
            match PKey::private_key_from_pem(key.as_bytes()) {
                Ok(pkey) => pkey,
                Err(_) => return Err("Invalid private key"),
            }
        },
        None => {
            let rsa = Rsa::generate(cert_request.key_size.unwrap()).unwrap();
            PKey::from_rsa(rsa).unwrap()
        }
    };

    let mut subject = X509NameBuilder::new().unwrap();
    let subject_string = cert_request.subject.as_ref().unwrap();
    // Parse the RFC 2253 string and add each field to the certificate's subject
    let mut san = String::new();
    for field in subject_string.split(',') {
        let mut parts = field.split('=');
        let field_name = parts.next().unwrap().trim();
        let field_value = parts.next().unwrap().trim();
        subject.append_entry_by_text(field_name, field_value).unwrap();

        if field_name == "CN" {
            san = field_value.to_string();
        }
    }

    let subject = subject.build();
    let days = cert_request.days.unwrap();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(&subject).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.set_not_before(&*openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&*openssl::asn1::Asn1Time::days_from_now(days).unwrap()).unwrap();

    // serial number
    let set_serial_number = generate_serial_number();
    builder.set_serial_number(&set_serial_number).unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new();
    builder.append_extension(subject_key_identifier.build(&builder.x509v3_context(None, None)).unwrap()).unwrap();

    // Create a SubjectAlternativeName extension
    let mut subject_alt_name = SubjectAlternativeName::new();
    subject_alt_name.dns(&san);

    builder.append_extension(subject_alt_name.build(&builder.x509v3_context(None, None)).unwrap()).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let certificate = builder.build();
    let certificate_pem = certificate.to_pem().unwrap();
    let private_key_pem = pkey.private_key_to_pem_pkcs8().unwrap();

    // write to file using name as the filname prefix
    let name = cert_request.name.clone();
    let cert_file_name = format!("{}.pem", name);
    let key_file_name = format!("{}.key", name);

    std::fs::write(&cert_file_name, &certificate_pem).expect("Unable to write certificate to file");
    std::fs::write(&key_file_name, &private_key_pem).expect("Unable to write private key to file");

    Ok((certificate_pem, private_key_pem))
}

fn generate_serial_number() -> Asn1Integer {
    let mut buf = [0u8; 8]; // 20 bytes = 160 bits
    rand_bytes(&mut buf).unwrap();
    let bn = BigNum::from_slice(&buf).unwrap();
    Asn1Integer::from_bn(&bn).unwrap()
}

// #[get("/cert/{name}")]
async fn get_cert(name: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let cert_file_name = format!("{}.pem", name);
    let key_file_name = format!("{}.key", name);

    let certificate = fs::read_to_string(&cert_file_name)?;
    let private_key = fs::read_to_string(&key_file_name)?;

    Ok(HttpResponse::Ok().json(CertResponse {
        certificate: certificate,
        private_key: private_key
    }))
}

async fn cert_page(cert_name: web::Path<String>) -> impl Responder {
    // Parse the certificate, read pem from filesystem
    let cert_file_name = format!("./{}.pem", cert_name);

    let cert_pem: String =  match fs::read_to_string(&cert_file_name) {
        Ok(cert) => cert,
        Err(e) => return HttpResponse::NotFound().body(format!("Failed to read certificate: {}", e)),
    };

    let key_pem: String =  match fs::read_to_string(format!("./{}.key", cert_name)) {
        Ok(key) => key,
        Err(e) => return HttpResponse::NotFound().body(format!("Failed to read private key: {}", e)),
    };
    
    let cert = X509::from_pem(cert_pem.as_bytes()).expect("Failed to parse certificate");

    // Create a Tera instance and add your template
    let mut tera = Tera::default();
    tera.add_raw_template("template", include_str!("./template.html"))
        .expect("Failed to add template");

    // Create a context and add your data
    let mut context = Context::new();
    context.insert("subject", &cert.subject_name().entries().next().unwrap().data().as_utf8().unwrap().to_string());
    context.insert("issuer", &cert.issuer_name().entries().next().unwrap().data().as_utf8().unwrap().to_string());
    context.insert("expiration", &cert.not_after().to_string());
    context.insert("pem", &cert_pem);
    context.insert("key", &key_pem);

    // Render the template with the context
    let html = tera.render("template", &context)
        .expect("Failed to render template");

    HttpResponse::Ok()
        .content_type("text/html")  // Set the content type to "text/html"
        .body(html)  // Set the body to your HTML
}

async fn create_cert_page() -> impl Responder {
    // Create a Tera instance and add your template
    let mut tera = Tera::default();
    tera.add_raw_template("template", include_str!("./create_cert.html"))
        .expect("Failed to add template");

    // Render the template with the context
    let html = tera.render("template", &Context::new())
        .expect("Failed to render template");

    HttpResponse::Ok()
        .content_type("text/html")  // Set the content type to "text/html"
        .body(html)  // Set the body to your HTML
}

async fn list_cert_page() -> impl Responder {
    // Read all files in the current directory
    let entries = fs::read_dir(".").unwrap();

    // Filter out files that end with .pem
    let certificates: Vec<String> = entries
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() && path.extension().unwrap_or_default() == "pem" {
                Some(path.file_stem().unwrap().to_str().unwrap().to_string())
            } else {
                None
            }
        })
        .collect();

    // Create a Tera instance and add your template
    let mut tera = Tera::default();
    tera.add_raw_template("template", include_str!("./list_cert.html"))
        .expect("Failed to add template");

    // Create a context and add your data
    let mut context = Context::new();
    context.insert("certificates", &certificates);

    // Render the template with the context
    let html = tera.render("template", &context)
        .expect("Failed to render template");

    HttpResponse::Ok()
        .content_type("text/html")  // Set the content type to "text/html"
        .body(html)  // Set the body to your HTML
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 2 && args[1] == "parse" {
        // Parse certificate from file
        println!("Parsing certificate from file: {}", args[2]);
        let certificate = fs::read_to_string(&args[2])?;
        match parse_certificate(&certificate) {
            Ok(parsed_certificate) => println!("Parsed certificate: {:?}", parsed_certificate),
            Err(e) => eprintln!("Failed to parse certificate: {}", e),
        }
    } else if args.len() > 1 && args[1] == "cli" {
        // Run in CLI mode
        println!("Running in CLI mode");
        // Your CLI code here...
        new_cert_cli();
    } else {
        HttpServer::new(|| {
            App::new()
                .route("/", web::get().to(list_cert_page))
                .route("/api/cert", web::post().to(generate_cert_endpoint))
                .route("/api/cert/{name}", web::get().to(get_cert))
                .route("/create_cert", web::get().to(create_cert_page))
                .route("/{cert_name}", web::get().to(cert_page))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?
    }
    Ok(())
}