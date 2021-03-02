const fdk=require('@fnproject/fdk');
const secrets = require("oci-secrets");
const common = require("oci-common");

fdk.handle(async function(input, runtimeContext){

        //getting Resource Principal Auth Provider
        const provider = common.ResourcePrincipalAuthenticationDetailsProvider.builder();

        var responseKO = {
          "active": false,
          "wwwAuthenticate": ['Basic realm="apigw"', 'error="invalid_request"', 'error_description="missing token"']
        };


        if (!input.type || !input.token) {
			return responseKO;
        }

        if (!input.token.startsWith('Basic')){
			responseKO.wwwAuthenticate[2] = 'error_description="wrong token"';
			return responseKO;
        }

        let tokenbuffer = new Buffer(input.token.substr(6), 'base64');
        let decodedtoken = tokenbuffer.toString('ascii');

        if (decodedtoken.indexOf(':')<=0){
			responseKO.wwwAuthenticate[2] = 'error_description="malformed token"';
			return responseKO;
        }

        if (!decodedtoken.split(':')[1] || decodedtoken.split(':')[1].length<=0){
			responseKO.wwwAuthenticate[2] = 'error_description="missing password"';
			return responseKO;		
		}

		//init OCI Client
		const client = new secrets.SecretsClient({
            authenticationDetailsProvider: provider
        });
        client.region = common.Region.EU_FRANKFURT_1;

        //extracting username & pass
        let user_principal = decodedtoken.split(':')[0];
		let user_pass = decodedtoken.split(':')[1];

        //checking username
        const getSecretBundleRequestU = {
             secretId: runtimeContext._config.usernameSecretId
        };
        const responseU = await client.getSecretBundle(getSecretBundleRequestU);
                              
        //parse username secret bundle content
        let usernameSecretBuffer = new Buffer(responseU.secretBundle.secretBundleContent.content, 'base64');
        let usernameSecret = usernameSecretBuffer.toString('ascii');
        console.log('\nSecret Username: usernameSecret=' + usernameSecret);
		
		if (user_principal !== usernameSecret){
			responseKO.wwwAuthenticate[2] = 'error_description="wrong credentials"';
			return responseKO;			
		}
        //end checking username
		
		//checking password
        const getSecretBundleRequestP = {
             secretId: runtimeContext._config.passwordSecretId
        };
        const responseP = await client.getSecretBundle(getSecretBundleRequestP);
                              
        //parse password secret bundle content
        let passwordSecretBuffer = new Buffer(responseP.secretBundle.secretBundleContent.content, 'base64');
        let passwordSecret = passwordSecretBuffer.toString('ascii');
		
		if (user_pass !== passwordSecret){
			responseKO.wwwAuthenticate[2] = 'error_description="wrong credentials"';
			return responseKO;			
		}		
		//end checking password


        var datetime = new Date();
        datetime.setMinutes(datetime.getMinutes() + 3);
        let resp_expiresAt = datetime.toISOString();

        var responseOK = {
			"active": true,
			"principal": user_principal,
			"scope": ["/*"],
			"clientId": user_principal,
			"expiresAt": resp_expiresAt,
			"context": {
				"email": (user_principal + "@example.com")
			}
        }

        return responseOK;
})