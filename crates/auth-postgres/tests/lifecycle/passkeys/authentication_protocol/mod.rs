mod binding;
mod verification;

use auth_core::{
    PasskeyAuthenticationOptions, PasskeyAuthenticationResponse, PasskeyService,
    PrivatePasskeyAuthentication, StoredPasskey, VerifiedPasskeyAuthentication,
};
use uuid::Uuid;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

const ORIGIN: &str = "https://login.example.com";

struct Protocol {
    service: PasskeyService,
    token: SoftToken,
    realm: Uuid,
    owner: Uuid,
    id: Vec<u8>,
    encoded: Vec<u8>,
}

impl Protocol {
    fn new() -> Self {
        let service = PasskeyService::new(ORIGIN, "Example").unwrap();
        let owner = Uuid::new_v4();
        let (options, state) = service.begin_registration(owner, "Account", &[]).unwrap();
        // Real library signatures; UV is simulated only by this test authenticator.
        let (mut token, _) = SoftToken::new(true).unwrap();
        let response = token
            .perform_register(ORIGIN.parse().unwrap(), options.public_key, 120_000)
            .unwrap();
        let key = service.verify_registration(&response, state).unwrap();
        Self {
            realm: Uuid::new_v4(),
            owner,
            id: key.credential_id().to_vec(),
            encoded: key.encode_for_database().unwrap(),
            service,
            token,
        }
    }

    fn stored(&self) -> StoredPasskey {
        self.stored_as(self.realm, self.owner, self.service.rp_id(), &self.encoded)
    }

    fn stored_as(&self, realm: Uuid, owner: Uuid, rp: &str, encoded: &[u8]) -> StoredPasskey {
        StoredPasskey::decode_from_database(realm, owner, rp, &self.id, encoded).unwrap()
    }

    fn begin(&self) -> (PasskeyAuthenticationOptions, PrivatePasskeyAuthentication) {
        self.service
            .begin_account_authentication(self.realm, self.owner, &[self.stored()])
            .unwrap()
    }

    fn sign(&mut self, options: PasskeyAuthenticationOptions) -> PasskeyAuthenticationResponse {
        self.token
            .perform_auth(ORIGIN.parse().unwrap(), options.public_key, 120_000)
            .unwrap()
    }

    fn verify(
        &self,
        response: &PasskeyAuthenticationResponse,
        state: PrivatePasskeyAuthentication,
    ) -> auth_core::Result<VerifiedPasskeyAuthentication> {
        self.service
            .verify_authentication(response, state, self.stored())
    }

    fn restore(state: &PrivatePasskeyAuthentication) -> PrivatePasskeyAuthentication {
        PrivatePasskeyAuthentication::decode_from_database(&state.encode_for_database().unwrap())
            .unwrap()
    }
}
