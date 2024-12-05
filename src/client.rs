use num_bigint::BigUint;
use std::io::stdin;
use zkp_auth::auth_client::AuthClient;
use zkp_chaum_pederson::ZKP;
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let mut client = AuthClient::connect("https://127.0.0.1:50051")
        .await
        .expect("Could not connect to server.");
    println!("Succesfully connected to server!");

    println!("1. Please provide a user name: ");
    stdin()
        .read_line(&mut buf)
        .expect("Could retrieve a username");
    let username = buf.trim().to_string();
    buf.clear();

    println!("2. Please provide a password: ");
    stdin()
        .read_line(&mut buf)
        .expect("Could retrieve a password");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let (p, q, alpha, beta) = ZKP::get_constants();
    let zkp = ZKP {
        alpha: alpha.clone(),
        beta: beta.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    let k = ZKP::generate_random_number(&q);

    let (y1, y2) = zkp.calculate_two(&password);

    let req_register = zkp_auth::RegisterRequest {
        name: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _response = client
        .register(req_register)
        .await
        .expect("Could not to call a register.");
    println!("Response register: {:?}", _response);

    let (r1, r2) = zkp.calculate_two(&k);

    let req_auth_chal = zkp_auth::AuthenticationChallengeRequest {
        name: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };
    let response = client
        .create_authentication_challenge(req_auth_chal)
        .await
        .expect("Could not to call a authentification.")
        .into_inner();
    println!("Response auth: {:?}", _response);

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);
    let s = zkp.solve(&k, &c, &password);
    println!("{:?} - {:?}", c, s);

    let req_auth_answer = zkp_auth::AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    let _response = client
        .verify_authentication(req_auth_answer)
        .await
        .expect("Could not t0 call a verification.");
    println!("Response verify: {:?}", _response);
}
