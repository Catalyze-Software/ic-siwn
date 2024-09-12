# source .env

dfx deploy ic_siwn_provider -m reinstall --network ic --identity catalyze_development --argument $'(
    record {
        app_url = "http://localhost:5173";
        callback_url = "http://localhost:5173/login-icp";
        salt = "thesalt";
        chain_id = opt "testnet";
        sign_in_expires_in = opt 300000000000;
        session_expires_in = opt 604800000000000;
        targets = null
    }
)'
