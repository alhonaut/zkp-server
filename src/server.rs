use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use tokio::{self};
use tonic::{transport::Server, Code, Request, Response, Result, Status};
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};
use zkp_chaum_pederson::ZKP;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

#[derive(Debug, Default)]
struct AuthImplementation {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub user_auth_id: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // register data
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // authentification data
    pub r1: BigUint,
    pub r2: BigUint,
    // verification data
    pub s: BigUint,
    pub c: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImplementation {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing register {:?}", req);
        let req = req.into_inner(); // to have access to private info
        let user_name = req.name;
        let user_info = UserInfo {
            user_name: user_name.clone(),
            y1: BigUint::from_bytes_be(&req.y1),
            y2: BigUint::from_bytes_be(&req.y2),
            ..Default::default()
        };

        let user_info_hashmap: &mut _ = &mut self.user_info.lock().unwrap(); // lock to prevent reading data from memory
        user_info_hashmap.insert(user_name, user_info);
        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        req: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing authentication challenge {:?}", req);
        let req = req.into_inner();
        let user_name = req.name;
        let user_info_hashmap: &mut _ = &mut self.user_info.lock().unwrap(); // hashmap user_name to struct

        if let Some(user_info) = user_info_hashmap.get_mut(&user_name) {
            user_info.r1 = BigUint::from_bytes_be(&req.r1);
            user_info.r2 = BigUint::from_bytes_be(&req.r2);

            let (_, q, _, _) = ZKP::get_constants();
            let c = ZKP::generate_random_number(&q);
            let auth_id = ZKP::generate_random_string(12);

            user_info.c = c.clone();

            let user_auth_id: &mut _ = &mut self.user_auth_id.lock().unwrap(); // hashmap id to name
            user_auth_id.insert(auth_id.clone(), user_name);

            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            return Err(Status::new(Code::NotFound, format!("User not registered.")));
        }
    }

    async fn verify_authentication(
        &self,
        req: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing verification challenge {:?}", req);
        let req = req.into_inner();
        let auth_id = req.auth_id;
        let auth_id_hashmap: &mut _ = &mut self.user_auth_id.lock().unwrap();

        if let Some(user_name) = auth_id_hashmap.get_mut(&auth_id) {
            let user_info_hashmap: &mut _ = &mut self.user_info.lock().unwrap();
            let user_info = user_info_hashmap.get_mut(user_name).unwrap();

            let s = BigUint::from_bytes_be(&req.s);
            user_info.s = s;

            let (p, q, alpha, beta) = ZKP::get_constants();
            let zkp = ZKP { p, q, alpha, beta };

            let verification = zkp.verify(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &user_info.s,
            );

            if verification {
                let session_id = ZKP::generate_random_string(12);
                Ok(Response::new(AuthenticationAnswerResponse { session_id }))
            } else {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!("Failed to verify user proof."),
                ));
            }
        } else {
            return Err(Status::new(
                Code::InvalidArgument,
                format!("Failed to verify auth ID."),
            ));
        }
    }
}

#[tokio::main]
async fn main() {
    let addr: &str = "127.0.0.1:50051";
    println!("Run the server in {}", addr);

    let auth_impl = AuthImplementation::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Unable to parse socket address"))
        .await
        .unwrap();
}
