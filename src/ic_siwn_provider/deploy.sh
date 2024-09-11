source .env

dfx deploy ic_siwn_provider --network ic --argument $'(
    record {
        app_url = "http://127.0.0.1:5173";
        callback_url = "http://127.0.0.1:5173/login-icp";
        salt = "'$SALT'";
        chain_id = opt "testnet";
        sign_in_expires_in = opt 300000000000;       
        session_expires_in = opt 604800000000000;    
        targets = null
    }
)'