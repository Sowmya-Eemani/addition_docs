<!DOCTYPE html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Protected Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #ffffff;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #4CAF50;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #4CAF50;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                background: #76B852;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Protected Page</p>
                        <p></p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Remember me
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="DECRYPT" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
 * Initialize the staticrypt module, that exposes functions callbable by the password_template.
 *
 * @param {{
 *  staticryptEncryptedMsgUniqueVariableName: string,
 *  isRememberEnabled: boolean,
 *  rememberDurationInDays: number,
 *  staticryptSaltUniqueVariableName: string,
 * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
 *
 * @param {{
 *  rememberExpirationKey: string,
 *  rememberPassphraseKey: string,
 *  replaceHtmlCallback: function,
 *  clearLocalStorageCallback: function,
 * }} templateConfig - object of data that can be configured by a custom password_template.
 */
function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
            const templateError = "Bad password!",
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"23dfaabc22ea1686297f6e45463a81547031c57b004fd1a8520ba6a8fadea86e569b27ee68be3bd86ec15840f396e2c7da79d59a5eee4205a137d13ca6379e99f7343ca0664ec8f048cc341139a83dde5a8c4facbb099d8439a4533b67136699209b89eee2f4b67e8ee1fc8f70c4667137e46a2198f9249f6e0ef3e3bac11cb7329fa431963118c2be86e706e1442ee73d873fa4e17d858f3ab1a3e18cea8ab8a5c8923dbafae73abb43e44ca94894418a5a9775561e37fb892f44186e16e4bb98ef04d4e0b8c0f97f0f4723d13a2c65e8fb6884a32a3e8fb888c2852ba1f59248297a2075f8d9d9899d71fee3da4e2f76d8845f6a7e5ed41617896329d5b23e02637a10feb53cb9152141d06adf819435bdcd05d73b1f455a480ed08c87d3454a66d3152a4376d7638726dae628d6c463d75a3b5554297fbf717cc72bc0614d44cb59b84b5d13f62675337fe843546156238836291a56049ea0185a3c73569080aab2c305a8219b9073c57d129f5a7a7f9e09019eafad9452bc04751c8a3dd13c3c09dc94c1095f22032f8d3cc19303f3c907fac4067c8eb09d11957fab18f5dfef1c8cba259fae44a680befc7a7fb8dd7c6c3df0428afe5da38e4ceab3fc048488376d15f2baf9b2cff994e22d49c1e6249949677a9b7484ea06ba65384f197c2b8ecb5c72be67168e3f0fb96155d0376cf10a7ddbbc3f346db5e9510b69e857abc830d666e16c99cdd7d6f2baa494d88a719a467b72c6878041329f34481876ec5863c7368cdf550f5fc14aa5d6d32fbbd60b32d97c6aeb1ac32d0faa7160ef6fe2b66f28741359e6aa6c51ed6e4af7a4a14e57b6ef2f701f05c1087aefeb6f042c8125cfb0f41fde1932e3a1dfded8586d2c3ed9ee154ba8d6e53f2bf4371eb35d24e557abc71dd9489362f09e2f9cc1e7acdca67656fe4b9166d4a724e637c7568b7bdf52e12faa13e7a6534015b79ddf1e66bc2b0f674d4132e763c702b3bd155bb1ce1551dc3f9a8ee5c516ed075cdf77d613e6d1e2fdb6e5ba591e11ea94d0540939f6efc5bd1625ce85b3b97bcf9825b56003bc9e4f66ca9c9f9a96736835c7b6e14cc13985f34c6950c6ab7e8ff9d6c1cf951a46ba936947eb4490163a8d70bca232cd8397e24e9a2ffca9c0aa8effdc73ccc9bf1b879d8ee3ac658c8828b7d7420beae520b01be6f8e34c3adf68b92984dda67593ba57ca9ccbcfb75f6213103d8c96a34331ecf507728b252e25c20787d02590e502bbfa655ba95deb7fb40b37bc928457696d14d5f1fa9bc84d0dc014d39b52df0a43e360602128e42bc358d3ddada35f61a27fc8af0991652f06bc03a619fe622af80f4727d0000bf8714d3e8c2ea9d009e8ea71d4879b787a6ab35dee6016510a52325f244d6912ab07f3c7b51eb04118ea4a4cf320709647c5d0b4f3f09d24e927b97891e38d9bf39691e92e1b30602de41125cb0c111074f683a33dcddfbfb005b2c2943ab2972cea440f44a4ab33564d2284b0f00cf903b929ec8fcd254d17b8325780556f711bc9ddac0bd514de3651e03df08625aef95234c009c1e06acbd76b7c4ce74df1409412fd336421e1fdf3e3ee0b49f3c5e28ee634f7bb86af8bea84177949df7d1cf621b8e8600dcb2357cbaca6266e301bea5fbc3f5904cb72d1af57f6ef191c361e2ef886b435d4ac58994fbf48153f7e9bf9cc2980dca1381208e6c05e50529faeab982e20abae974c85e79ddc0c323c69a15c653040dfa89b01194f9baf791f10b41e360b151f5288fa7d7c8a2814f4df624fe4aa2c005266ee83dc99aac8942b4956e8ab658e68b9a5256c4a4c7f57dbf30ea7ccb92e631363c14caa2010ce27fbee0a08ea95c9f851154f92b02a987a66769cd59deaf244078e7e28146abc081a77ae1ef15b769da32135fe9bbfa7d3196d0f618cc8fc48337a6208bba405c6bc5cccf4c23d122e504874872b3364036b65aaab295b250bc6af114991aa78bfaf08abb8898925cd2243a87be5050ec7203c26c6d0d3b9a1baa7e770ab57cc81d3f517f0d62923b08c5822e468eda02f96e189682ee2701afbf2304b6fb5c2d066c9bd8b42e4d104b435c4e32eda94a69f733c141c17d73e18237a1bdca5113b5031e89f195fc668a7e93e0a07a092772e15b2fe7c32927095e1c8c462baab95552d04e9c2a43a39e3dcba49276ee7220785d0f9a8470bd0ec2e66fdc52ee3509fd79a738af8c506510804a2f17c03bb83aafc8cf95bdaf27a3de83f711275224eaa54a9201ff60f3e2f8548ac50988bc0d4ca1d2fc825ed4075bffc3b9c257ad4bf77256332dc527b8b77ae2f5fe37e6d5ac2c0778e32de74aad8cebe161c2fe390291f1a03d1d5de47a0ec0b5acafeb30744d4ebc4abb46602c6132f02bdfe9d8410edce47efb260e0d22eba0f4434c217d6930fe557e13d46780fa727d8f9aacf47e1f7e88c5448e2061b8c4e120eded1433d34eb498a7711a1e22627c8837251e6d263971c2248402af4133a1f8859c80a29ce365412fbfaa6a9be4097a14f6d4932751df449f5d2f73467cf7e645dd964924d86de6c0d960748e2e9fd640b20bb4959a3e571bc8f16ca7a368d3a65beaf72c2242db6b3747cebbe141da326476085f8f341686c97ec23c8d1ec87ac342233aea1b319f60c0fb4fefcf4f863c599b34111114c4a54c03f238232c8ade2e07cea5b8c8664407018888a73422bf43cb951bb11a3a508fea959bb3c76c2381ce3bc1b274cf403cc62108c4c1e7f9f2900659174e7f1e5a402a79665e921dcafc3ca18c02b0dbae03c7415c8f3f049f0b87fdf58e3127f78685c4dbc156eb8d44bd3d082b0ecafaa8099fef3a82ba6b49fa255685d91cb678b83ac5f1269eaa329b17426648a16204a7963399c2bc49107ae6f270524e63bee9dd3476f0051b7339fc301bfa21f2c11336e81562c9aa8977d36650d37d5cef1003544cfa23ed41b6aeaadec8540af28da8a0cde3762c9e5fd035ad68b3fe0818690238ff54bb7d6f57179124287e45b7d4f93cdf9f213f8b3f1210088758f5faf008b5f61bf6961841e40d232db18de1aeaf334336b837625e059fee2eff90f215d6d7b410ea02e6a2d8cfd2c1e1d3bfcda953c76e186ff14d8fc27e6c6ccb13d204502fc337cc1f0d1ed0a819ab8774b52c482bd4e1f427ea67b2e6e6c2306a8c737e7e51b39ccadd9ca361c03f274287f97eb1685f3741fbac1474d43e70f5dd10eba97ef27d648f1304fab60d80372c507000858c7702e7bb992f6ff67d64c5ae144da56cebee618ef61d22913a935855c739f4fdf42e6163c7c2166786022a47c42a56ca48c4dc3a5d00058dd743b26dbd4d9d0c04f79f2afa0ce63fdf4442fb09c96abf9d2a5ee5109ca5bed1e1af095648d6f283f4643f469d49a862570e66e055655156152403a5d3b85e4d578371a03e9f9d12092f591027f2534244e9b9b76275f764e0a6ec86b51a210e61351c1da9a851eb53fa1b83eca26e0560f72d818dc1f952763c62ff57714d54adbd0a840f4b0224d50e66370cf6efa59398ed3a1d58c38a6c0fff94ded574ec65e5fa2216eda5892e07902c88747168476cb411902f56e468b538eb1275f3603085e53023c69be59d8008a0c2b429202334ea3b9241981508822f699f2487c0fa6dd6ad7deae1ab98deb6a7453a967dba2c67968e8d2534c6fa546bec89ea960f70847bb55d860d1fbc6c82976aa2913187fe68afbc0c2f72e57de777775cd7d32de6073d7be37dc0715fdf43ec578fd6c201e8371154604572514ce218c2e7b45b6de52251fda317c0c2a9adc5476631795a6630477c692855f09beef184c49702825b9d65e1e16122c85d9aa9bceb155039d468dcca889d84a8725999dd52cce2b747fc922f78f750b6fabd15858da90e5321b26333a3b70a576951ae03984c1eb514c3c911b3787a6b69bc22a7ac224cf6850e6ad2358687fc7e9cd8288bd6725688f13d1813f78c5ab97a23b9b035c26bd871bbcc8db0649781c52e1224044f123432d2559b7dbae12b0758d12d3062fc544ea5321e3b400c776b24ebdfdc12e05d4ef46ffb80c2af28502c00fb38eb6d80c99d98bd266bc35c79c1804092c3956be3e13c6452af3e0ac93ce79f604ad786d8a640868fe46d5321a6fb9bbeca4bd60790a8ea4642b1722495ca9532ed5d15a379bc4a855596e45fd323032728c74118aadeb1275c06741572e0d6cb3b5efe8fe610a9296e667dd21e2de8a30021bc32504e8417a17dd7bd98ad3f0ed4969d4dde0cd7a09d41c2464451ea15da02a96b3870f9d26455767733dc165cd5ed6edd353d968ca0105f0fd0abe27d6f1d1e5b5414bcfe6ef2e0403c2e412b392da8d5438e06378cab6c62121f0dd8a66fca18cc83d7d44603700871e44d43934d0556eebf0b33bd300a9ae821c0c0abda594b253e6cc0802c72edf32f60ccbabf23cc99a30b46b126c1f9fc5fa56fa64cdb040bc299afc6bb955a41ba1b547caa14ff5c4ed3b0a1a2c2b79940d1ed8f1b8709a6ba742bc203432a8bc9691de76f42aaf03600faaeebe4ab6a33c5ac41ff54d81d14c0550fc422fab7fa4895e6bdcbc06d8378683c59f0c6b979386fa040c5f649afe1b1992f839237238fc3efc7b209c57b3a79b39a70f746678f8b601c2aa4f1b21a03aec95c79af939db5ed03a31b742489e7384915629fd28407bf9695ecfd4252c60cf019ba5831fe492477db3fca6ac705bf679938a00053838b999e1c5941f753fae856f079b51080d95b79387febb81fdb8e4aee129cbbde2f2a38f11ce36139d51703ef9950620884d24929ae4ec0c0589f94239656d8b33217dea8fa7e81df6d79e4c83d6380c95c9b3097bd6fa9ab936b93f5c86adf42da6f5dd1155bc10932844ae4f7efa8bc479a30394d76a90628761edc60a1b008133ee9316307b70fcff32e2d180e0dd7aa84cc0373295fa7f4cd123b730cdbdc5a7289709e7e58b45da787b6197c03d9bd2a844856206b297c079e82939c7654bac6d7618e6ee066b114c29a1c9d22fc0889ae17da32fc2b2c71f945d5cfde5a927c5110457a21126aaff9c8f6bbcdeed4a188908feac1cb10553faf5111d3e4b118363eda067bd4c263dc96d731442d379dde6e16aed1e4383fea02b9e41c4c36414c9555e0a9c60b9a1e43f564574e5e6d89ef20b3abff478c92f1718118b8977b3ea40cf52034b683695ab74317b7d5994780b9d76d9a0d021503cdc75831f179fbd5f059e0bfedd7e360fcd3db68321086108a762dc4945907053e83920c917d06b1053072b4be033029add3057e842f26e5194cfa2c821dc81dacd47c3f8e948d614d3edd407ccbca4bb6be3f033f9b56dd9ee300b2af15c085e2855dc70cbc0c31fd41291d590eff43cdcedc924a866a91fa97533434f8f9aa8b05251fa5f5877d88fb9e36d022e0bc6b5e25522d3faf67f007ad0633be6c066184c3dc29c8acbe982549dfae59ee564f661797658bcb2be77df02b07dac3c59204c541fdf6d2ae4539c6a7d9b5d14ae2c26ad95911a5ad4f07ad34905b5bee9b86a5f3c72c0158b4da9f5585c41caee9b07e83abbee2ca1bb6650328e6c38a5cb6600b72baaeb05b00d961e65ee84bcb5de8abc47ec8938353c18ccf48617a4befa8c413a3670536cc686a09f82cf285c50e78e078fd1fb31a36b188b7786e937f42766f150666ea755dcf4768fe9c0589ca0e1694481157331e6db552eb7d98bffc736abab69ef7e4268cf416a33f25445ea03bdbab6720fbc09755a00113fc07f1851a932feca2aad720654cd2a72b551c444aabba0043d8ad7fd757cabe3302be21ca7ccdd1225b85d5ff1d8c47e44ec282b6bf807be74395817e53c49c600a6633ec5fea5b6d55b65d0cf0ae581ac4c4ee553d2205df1b892ad4d6296113db0987d3e2a5e309115278a8c5796751f27b780abc5de452206fb67850326865661da8bd1bbd6f9350b1b2b4974f03c6da3eac4502ed6fe3d0e92f81854e8c0313b6c32c229107dd57205104c65beb7792b071b6265f288c0ba7778cf2b433abf09a1817b035a809fed8df85eda066ea871cb5c15cddf76daacbabcdc4e174fd306293780f2eead42d0e6d15aa5b5aa1c35c19ccfea320c79ecfbdcc53dfa1c3f6573f40070af0d868fcf301d0174f381148b693bdd022bc3de777fc37cf3c1b5945339b2d12cbbc457091391581b15ecdf1dcacfa90a4eedd46c30d3765c1b57aadbfe2b70e45f8561a6af2d02c2ae4ca2914ae41aa04ddb3539ac7a85cc087ce1fde2f6c2591d1b92324db7ca09e38336fc5e8a4f3f5cfa4ccaf4d93d47257c4119d26aa797b4101d523030caaf71edea6560d854298f6fb553c37553ff2eb7982f57b02ebb1654ee96975bf656e02bb11c95337045a4971b95097a4ce24ba84c097fc97ab1223d7fb5dd2bdc01c4dfe1a5f8e896358707c5075b64bdba43bdd1402a9530ea34f4a65af277516822e42b8e4c29d589dd5be0a4565329d8aa2d3b483a400e3d08ad0a37543f7908b6575a82f42bafa1d4f4e8b6f479af82cdf3f4bd0f38fdd3b5d2472ecf9cb0b4d0635152aff512c82b627f01e6b1fa46f99e2045f215c38d3157ca81c99582881be93bf17d4b4b30e9c80911e51a85da49dcaff5ffa1dfc1710dbeaea1e8c01c35835d4c3f526a4f96d4c07a681e382daf2d1fac369e869f0903c86b82e4cfbb0f0523c54f72184f5740ca894d1d7d089e439073650bb19965e744e56731c2f6608f8d819c8b8dde1a48b650a777f197c35663ce21e55e8756e7c970eb890e379389c965d3a10a89fd807a699a8a32f5ad90357c4d4d09fa84665ed249e63b259f849c00226506f0edd783b41fb0dec026a477992a25aae14ddf0abd4e543c62404e39434fe4472b7cc61c4b29f90a41d3c1d5b4a841f0dc6c4c7613769fbaf6ebb3d0a91a8fb4a6c3d764e5ca4ab9b3c3c4b7a3e8bd067c988c2f3abb707455e64240aaa28855773365fca569cff835fa7801200453139ea027d59cfad2fc5b54d49391fdc3e3cb47c6e1f61c9b4a4880325f83aca03a184abd62a2104274fd6c69ffea4ba93a8f3a87b41a5fc610d567f46b1cbc83d62e38dccb1a7bee442be07c0d3c3686f6fbba761ab2159e53275bf65b0df97999ef532dbe65160fb872c3adc38230a08bb0696f7e4981613e125ab279fb05bb3004445883b71ab5de13043f553f568a36adab3ef512d40150c343f09cf92bb1450572607b278c83ef59e28db080c54efebfe9ca1feccd626032500d852428ffdc83d5c348352eed06f0e844e76d9d15580b4ae42a8f6c6b548ca8875c5954620e5192fddd7b2d074870f1c47871cbadd9d41fe98b96eab0e1d749e41213f753f82c9e469b386d9feadaaf0e175218ee52f27d147159ae078320f4f83f774971c97cec9db0b91e7377290df0ed0abe7d724f0af16a7a3bcc69d42f4e54af3a3590b1e29ce2dfc9405727391d9f82348e9ab1b64111be8391f122d15b8695fa90aa1d4b070f90a10dfe2f4c3e61898ec898c35db383f92539e5f210fddc1875fa5c475c1a82fbb680bb32fd2a41555add4028bc3ca1589d7d664773cffcf6d3b157a1775ecf4e4bbb992dbaa1f3c10a4d1e82007014d08faccdffc8a143659aa5fe0e2194b05b3f2fe37cea0618ed171ae1d82e6534f3257e05e6bcf77353adc22bf65bffe0a2569ad6317c2f7aab8dee4e878f89113db024e4d5e465de45b3e7ce01b83280b79eeee6f72ceb1a2484228f208b98c280e3672d4f93aef43a4044f8a5fb105fc3100e7cdb32e2bbe1aeb3c39fa08473f8c2815ff35b8e04ed757f312e2518d12713c5ceb11f9996e4c7584644ff865b8a99a1b966bc65bcff2a57b1837fe623ead8a7ebf179044cc43aadd8d009e3f44dccddc62a3fbafac96191f644437077cd91a78b924a382163031774354e719d9f6d0c73e32c2fa0d64fc2eafc366fef0525087512ed22b5a5f969dc60292cce5c7629b97677cf20d04e9af93bdfa0c17911e5c015a37654e325e25d17c3cb58f7dcd91921fb3f50e26c3e9d6b12ebdee069dd6ab0c58e71ea2c234023410ac236ce89a30903888c95a9af3804344a892acc64a0778bc2418a97353c6de4e46467579d15dee2b7f49e08d15b92e776bdf5ef1f6892a022af0638cc9163c30df049cc787470c859a6e80fa83050d9754f398236940da663f07f7b266426b5dc2b93d6d798755d72aa0888f6544562c6f66e2bf4a46a0b3237a2fab69446698ada2fac8dde61dc37bc26802ac9c92218b0f736194d06b430ac36c137e4e3ec5ee583e6525e9d786e2dd4f42f739843b0f4b1817f0de852204b557673522c53c3e84577a01020823e41259d00cc6438fdefe28e58bfc4b66c97d8bb6d891360dc59467187a3c9f18749ad5309cbedcbef1b6439286fa55da6fd294d5d40988f8a0d127b9741a9ea5c6456c1bbc74b9270019b9bdb45940023187c30c1d91ed76bda222b40c35131f6fe3007b35ee67efad9d297183bfd756d32005ffa8781571fd1143b605b74fe671074c59dda50ea3aaf61cc7c8d6129df7192a962154cff6594cb369c1311923a931c28c85b591c587e943719fe09a8e77397c2acc1e78cbedc55094d84bd225c5cd8a246529cbb2be66d952ef6a635b49a2f689466cbe5451347072d6645ee51a801f80ad9b2aab3e363557b384d23d585431324aa11bdcfd2dcae8063ba43f9a9689bd50285db4d5b3fadbca8b4d8cbc1c9272bb680d1268c6e384ed4c19779453f82a5d8e618e61873be2e35c6ad475681cad1740fdfb8d7f84f89f634f35a5af018467ec9874bc44faf0e223a20984d7044f4a2808851a6e365235aba1fa7ffedf1c93bdb2da43fc93b9985342ec0d8ae55c129fe06cd2fa020d54cd65cf9df68343d276867828e8b767d63532cafc030aa181ef5fb60b1240332c15121c6561db9363a6f3d1fee2f14259754a7645e12ffc05d6e217c0c57203e12ad07530d677310bbd7f79e0b91d7b49a5fca369705ca6ac00220966a7a223dbbba319d94ea4214c2ce54152b9b35b430be1b6ea0c7b5137a07ce018ce940b9b6dea259bd26a0edd61c0e7b65b17eea6973f7dcb0c1b6f75cdb75399b58a66e05b452e790916b6c5379e9c2fc43921dd60ee71a17fe93ba5defc28718c85d5d33f3c5dc821746ab479b1828a7a77e27fca3a29a731548bdae5ff52f29352ef8e94f134694e2aba56039bb5345c2f8e9f173b5859177a6b01aebea85d76faad712f8e95d4634f0799569250c0c1f9eb4681d1f0a50a1928063e956f32caf0fe2c4f32bddd87aa2aa05a8e1c718620bc0083e2d015b3cca6201e1627a151380eeb10c29ccd7e057013b4d193c4d6f67bf5eecbda8049d0d832c24d18c1583e70f0795253e04e160b962a61823b9fe9bdbcf22abc6db9fb4c3dd6701b0a4967896f5c8068cd33b5de10beeee3a9521f24cff4cba93c4b4eb739d620dba234e438ad23f27eaaa1ed5d54405c61cf0229e0f1cd41307ce9a38cefb8b6e71ff93e7fbfc2f3a38f7c2f9b37afafcc463a41486f003b7781c58b749e24875ea967d15a07ec478edf1b17ac30c386dcfd426827dadfe6911986aad47cd7852cdcc278625f062a81705716b33603bb0c3e55916700d3db77aa9fef72e6a3e07d8638c2b8e576a46fd156cfda63d543b4323025a3edae718c5790bcbd534081413fd14ec0ad7e3112943a72d30a761f8971d27b1da3029c2ffb5641df8f3d4e452ef02b4746b3e86be9e841ae6822efbd9d2ebf75f0fb5f1b1bbaebe8443a6ed9c368fb4eac149375ea76126f202528766a5a9a259e0d42ff207fd6bfa0c1309b70c23ef7b7313ee78cb123be0ee32d0c2f28a3e98045cd8cde789995edf8a59750904d6dc34bb8eb9087143246af7e54bc8948f8dbf7189d382a1823667667737bf0b27fc13c8303ae26ddf12ff6519f2333386a65dcaa97572f0aaabd35cf0aa30f250dba8d840b8466cbe420916d1482ebaac76a83f434f6e3bdf9883721ad971d8931a46d7a6498f28ae8ee190ab65bbc2519222b1bf20bb615d5357ac822a2ee017914af78de69ad1f2730df4e95e6ba308d3c45cc43e50c2e580c17396aab4a181bb25130f5a64676cf59f006eae04e1b0ca0464f6d9adb42f503f2a9cadf470cfdd30376992483932f534ac5f13977284cd3a6169cbdcfa673bcc35e2556a5a982f06c3b2ea7eea82c8b27423cd0807b72328449ad8f6b37e9fbff6454c85b08271fd5e61290872e05a82b369f8737094bf3371e947a47923ad39885549063002da8508975caf1acadf51394fb5db414e4de0b88d7252218c70bd3e8d31febdc52b2132987d83f6355eab4368a91431bb234258be7c432aacb40aecf3121445c22ef41ebce0a72e272bfb0bb209c23bc3d1d6cb29b4fa52609490d4c67bb8cc5093b0539caa958729b496c35bea4dfeba1e70007c908eb1195f9b658143b5ad252ae46357b0e489bd1f14e4fb44da65b18a72bbb7e1512af4d912025d49e6d5e0b2a8b2ccb0780d1cbb4a08559a23acbb63983f3a177dd34d18bf6b98bb591fc9a564f335746b2b6b871a880daa51f1654ac268144b0e9b0b409f7d86a2c4ab1fecdce9af79066aebffbd9e03ebdd8afb5e96ffdd2ccaf192fd6225e1086bb574128aad1f3b54163164bc709b4dd73566fa0f137f4154114fb23f7b1a8fbe35c91bef0489babbbe092294cd6b2435980357eaba953e939ad79c75fd8de3da4751d28e80a5015cb8afae795dd9d9857207c31a3e2ae9f9e71bd3a7e00ccefcc0d9d05d30ddb567231cf548ab7e07f3e64409bc2cf0a526dab72d7f5c1e2a612e6074559d4d725c55b7f0a60799dc11ea040fce1e9b74cb75f89d0ea9f908a0e6bb07a3a5fcf41a0b4a829e1f0f35449959076a40579c43b30974ee4e95f4a38adc5c8761fe0c8583a131caeb415436c3eb25c6a7ae9cfb3f1b570a3886d2d62ca2fbd980855b281f706624082c53cee4cb806e30a177d6de8ae2c3a60f5186b40c0a533ba2bac1bbf47c33af93534f89826b938971525188f260f2aa598dcab370fe6ff6c786b5e5b6f696293f8b7bccb1939274a5578e1fb283e16c4f909aff713c348ce52545d3524c4789dba324c0d842f3e768bedb17f2ddcaf57cddd79702d9d0155a840f56d95ae6d586b588d31ec521e18bdcacaafde927e0a059daaf91cc9b142aec4a11535bed5fb88409a40166bb270ea373545deb1fa5dc630676c1a7754382a55356b2f3f4f1ae5995576383caa1f4155a15dc6ef40907298741c10a895a5803825de57d8c278ea62fc139e8e2856c4773a4dd43c4cffad142d364cba206ca142b40630fb88c670988e987a1aba892cae0049c30833b4f4a175bfbd727d158a93f3515556513796c3203b397ce12b0a5d4c28688ecdede1bdc3fe41ca1f2ca4f8fc50d227bc13cc5664cd64483febed258edde3582620dd6ee3466624720dcd51a36cf136a9a60f7c996409a39d840ea3fd7136e4f066de7b192d294cda53b60b51bd4f93fe3456c88a0229a1a96706146f4fdebb7624fa9c055ba7a71a071453c3b0b2515960732f01711756a5421c4d521cf194a6c333a357d03c626d940d2430a993189f13513d4e2b349b75fc6c908b13c856d981c46091116c5051d7c94987591933a8b8c2dc43a8aa59d66a2e9c2f2fb6fb7666b4b34ccc522c834f667e79f2ade05fe6f7aec3bcf162cb5eed57ed9ced4c7b62ab8ba70857b7bada2d1c81df6a65fa0dcc125106b662a91df4d4ca8cb51427b485b2c0eb64791fde431f1fbc2647ea7ecf16c72116ececba848a118188b93f6d2ad4f12c56ee4ec702afbd1683256050a939c1dc687f744de4110970f925ae82a38f26922cb430a08a2f0293500a1614a25c6c934171400fd628879583a78f85380754dcd547a16a30cc559d976c4f037e3a7789e4da1e240467742902059caf6f99381cffbb40867137810f4426dc71bd7262e0c66ca9821c22802b6f52c8174837f4d3f722b904df85f381ee383235fb33626633a4fa8aa4a615ed6859eea1a1686419e2a737a6106dd3f5d885c9c24853cf1d8c995922ed15489e4f3492fd46894bca42207be768ab004ff0090dabb384ed36f1e694c291054fc7096834b72dff6335f6152e5a061d340a0931bc4a23bba77ee8cf36e70f7b2a73e63d843dc1767c138f580bb4bc40f7defb1f746fd7bc28317dd64056561f71af194ad76cca39b90ba1c6404bf222b6cd7a14fc72388c241f3852bf3154abc5858430be74401ef7f4823b7f7b84a7884141272135496f4ac691e0aea6b9cb4a1604bd883b7184bbdedf8bdbf1c4c9ebbdb092452c6e7733780c38ab62253b781c27c5c3962d62217a3a8e1721a443bcba5fa87a1ce0c92560b4243a0793c2f074f05736227715298570b44834864503ab7f9cff684d72df258ecd951aba8159ee7319490d565182466c456bd6f16c0d76d4e8deff90ef7e27a921a06b80796e32e3838db62b3ae57de840548eae0d352e9119c784a29f31951dbdddfbe4fc50a169228ea8d3310a9923eb2d58d2253724a25a5c5d1fd54db3379725386e600c713f296c66b3a394b2b2f5b34aeeddfb6a4eb8955e7dfeb5ce320c407f211ba359a0c602eefc420dbc99139baee07b72780d47767f949c682b221f4e3806638444b2f0e4645b8de16d8d559c423da4ea346df0e9d1e6134d8c386731e28730b4c0abe12b8166191aa26f28a76e529602f800a5c4c4a90889e02a43c376852b145496481820b8e8bec9fb6bf271ce5a2b141baf4dbf0e6bfddc98047944e36942919981f2a99fe324e02f03aafffb4fa328afc49e30011b08eac2b1cb8f093caf350523d9bdb1f73547b1225ede93d2d9621f71c88fe0ddaedf7ba19a3130df0b53f9db65690ad0223443ecc52f5e0d1fd7a9484af5ce4d846bc234648dbb34b8655d06661eb2b06809789445301511a338faa9d123eb5836b84631093df3ab9fe08ec32b5fd366a05aabc85cc1aea0f43b99b02d42f1cc47171087763d890ab0b1e737ddecbd79540418d3718fe211b05354f95b540330205b00094a406dcf6cc75ff60ac7314a38e00b2ebaf9f86dd245f8c3f4218e4751d0f862fd86c1b511719c0f40f00edecbeab061a0e8538432daae320c26a85017c5afc2da1c876fb9fdfe5e4163331d9989e9612f2b09d9ec95574c2297bf9aa50ee2e93470a5c31e4ca05954136dab8636e56de57aca5264b03c18d6778fa9d774efd2575f8d6f052247cf67f2f9e16079a0e7827687e043b394f920ba298a8ed258a1065d59edecfacb5475aca7dbdc34b3891757e3cb4d6757b4125a88d06a7d764c70d041ee9f1bf710cd184005761c7e963c0a5ea04862a44d717e2844ae15de7ede7faf54ddc107e6c23ebb879c7a4e3731814ce582934e317c3fc42ad2813c0938bb4cc54afb40e5f362e07d1cc6b2afb03ee4ee7001f04d27a35ca6be154066107935709d626cb087708a8451859117ae947f8675e70e8060936f67fd68fe49e74e6f9414895516afb6428fd1d59741c6f525086892194e6c9f3ce21fb184ae78a9da666418a3e9602a9cbe6d92e82d72038325a0a3b0ee68ff3a008146cc3db81ea029383644ce1eee65066daaea71ca88813e866d3206d36525c48a6d19cebc97d14028144721e953c53261ae77cd7c398c738f959b5141f6289082b486aee3ed43318f4459250df9e73699fb5d9d6328335dd17e9de8ee11408b6b9e2a094696c1bdb5528006c36766f95dd36d3604c75c8cff9cb5dfaeb4b405153a3e85ad66f47bad78d812cc890e0badf903f4adc8ad3d93c95bcebc1cbc7dc562b62ddc6a4b9e0125a82517a41e8449bdfc4e59f4b8920a405acfe28ff25ebf22d88dae6db8bba53b82d68b0d5f334a546ee41c65efc8ca7bc5d75353b4d1566367d48be2436758679be5dd00730079d4abef1eeb1b82e49a9b63cb04d15af0ef5e866f6d4242201cc6a0ec08e8247fbe376b4a9a227be1a6fbcd286b2b25f4c1f7dd16268eb2ca1059087c145cce59852466a94add31b00ccf088a6e44abedebadf096ca79239f5eda4544345131272f948613606b4e900be3a9911625a7137f7beaa0fa50401bb8496cce8420b70b04f546e1bdcba9080ad6c0b3c2ea2000b499efa922aaa824a9404d39e338595246dda8299c83e4517c506c4f47dca8bae3ca34e34c9993f7d5fdfd6c7f8dc0e56e73f3e236665ac3d98a1fb09063bf0136a726db280701023ef4252158d3fe0fcf4ce41aa404c60345711f8d84bc9d83ce36846676e11a1f2d482aee72726e83666b4d6302b282400b1ad79f7370bf8c7e4d324b2b09c257f750d0ec65943b820ebd071fa4d822854a6fa27b0696341ffef7fc51fd567d4faa6eb8a99fd2aba277852892bf0ff7381c66a65f8fe8cfcfa447ff4a47b95de44df6a151be36510a92337fa6ac2be34193e0adfab3de1a445f97dd5b222261c2b07901a3ae2956e5883e818ff159e7b90bbc09a6b9cbe0221d31f60fc2d3ac1d7df3cb2f3055036615e1981d0483e01eef13a1d8d3426115c9892b5b7af5d075db7d585d3ae5fef0491c49de4730116cf4cf2b65f66de0536531fa338e14f9e264e73f94471a5eafb094501cdf6e1e4c57fb816fd7c6caa7ebbd26450baa27f36e7871884c6c81882a283b8ff21e932af287ca98608cb14bd2f149c7e313391cde5164553204cb552fb311f225f831e50c2420b0878e4598b618d04bc3eaeaaefe29d9962c2187336ec67400cd7a6b2374de01a6f50a08e1c18e0cc0dc46b6eb8ab6382cd59a16857858e145546670d803691468d3be8657ca216e639cb21fa5057b0b5603e3925d891320cbbe67869b2f518666fe8b0a331984815213c64dbace84d304ee3d375464fcc387fed8993b4df8ecc0ea94affbc6876d4b9bb6e078ec838381d513bd7fb365ddcbe3879e3d131d5caee868a2b71ba5ae3d2870ecec0355a163af16eca769de6f8c92b8d2e774216ec88f3b67eb5af76520b819abb252b37d4a90b8771a987313c2c938e2826db69cef8e989bb2c5b9f09f234545c1aea5038d31ad59cb6ddc1f907b4505189977cda32a7381e7fea59cae365717960c3952b623ba08979c9482a0d839de408154c8c027fc6b0fcc62e3e2ebf886d215814a66d9763b7a0473a628a79d4614dfd855a3c7bf3db05136ebfe451d8c7176438c716cafcb951847f9b043990bf68f949bd961e346408f5c981762747de88b13cdd35e9b6624a9f6b59d13b314f80d4f0635733501919cfddd232cbb103191b07bb679168a02193f723fab790e546b8d44a7f3cde6e49ded35167b51dc791bf85284033779eb0b74c4bf33b33b83741eb5fe1bf150b0e79b30c987ebf1acea4ff58b67fdd51576238981bbd9c0755485a5f094e03e638464042a977ba95ab9b74a5d08aa7bc676a4b6a61114f29eb95176efe0af04a17908a7eff531d7bafa2b51581ad6d5a3152814421dec057b030c7cc9fe4f8faf616fb33a210e61cac674576afbe5b21b106d60dea4418dbee86ce5e78991ceccbff8367ad9e21b2f0d27f029f7ad63541c654762ea4d07c1a5ac1be41637387257226fc1f7160441fe16247fb27aafc86e7bf59e6fff117234e117a0c5ed0021a1c939867e39a399cac3c798dac20ab12a85816827a0eca0f196671b482f14df86636af056eee6413047164ad6e4661154791ef7617104f391e2abbfbfe6f1db4855dbe49abbeec491f85616febf872cd2483f1d6ac64dee85242316e1f073f3c91829ab0f4f90c49b229403afb04c1d5411f6f501f44f001bea4a58a1c7a5e289806ccdb6225d5e47a46ebf8711322359a73cb3a6ba27d12c590578990ae53ec46341abe034ca32aa93a38c854ad9e5237b66e604a45cd7054989d0becd1fc4963731c413955cdf59121cd2fc64fe2574a4b1d2e0b4d677762b1a1edbbfb0b195095b88de51730ad7646ee6654c8180bf65cf41ae9e586a4834ded177f01bd9829e4f388afd262c2c183667a8de9722ad59a052e9b88152d8573f016c4b515c2a13119e51eb71e4cbef38d94ecf0b569a72d4c405478250df85e9363acc108b7604252cbf81e0bd51120ee27472d6221c29e8c04caf0f7ae9692ef2ddb0d95359044d36c1fe046ebead51b1be365561692fbe08b45cc65dd12e94e2803bc4a6aceb3628d9dc9d146308e3c8d26d02f6ad606d55b4a1395bdbd697c439a7c8e9d34d3de635a4a35d7649df664131e5890b0608de297bb33c657285be64e3c35c156758786acdfa37da4276ee88403226050836220a9c38076e6674d9d8efd2e3e11d7b8c1747f54d4573df9fa2923c9290a5fc7315f7915d3e7306406a1e78ce13146d25d208243e8d599c416278107bdda7961c9d130431487d84e7bbc6174ebe292ae75014541e7ff1c881e6bd99fe0c970627b28d382f49aa85d7ec8ecfe2f928b17064658a8753f1493263ef590277b56a826c1ae9d188b02dfbedf2801bf2e01419939b50ddfc81cb05fec6f7ad8427a4a84d80b3ebcb7a9915a23ceb4befaa13b4a7065f807874bb9d591fffbccf207e146afaadc39759f74ec7c053690de132ddb2d38cc2c9469fcc34cd1a965e142312c5438e6db6aa9ef49b1099267f169b27aec6708012fee086dd7e0747d909993f0ab45ea94960b93ec16cfecd1fe55bfa3635391ea609d74f53da13fb9a419c5830dfde00fbbdafe99b3d8a9f023b53ec98529c4db09d241e741c23e69afad24c88e11f78ada57f63a840c82e3c2bf9c9dee38d7707bdf62b41c89be6f8ec63af03b3ec97a903fad2b38ece4a215841fb2948d9f8f410e0c1a9ce7ad4d0a891265320670f0a532085a35066baf4afa3e8b8e519916ee922ade8866b0f89183cdf25bb542d163a0df61650ffddd8afc9d1e5f92edd6ccfcd9639c23914c33f5ee9e173ceec2b3e7eab3b653665e62f262cad55b63a5ca55f0ac46e0ab4b9f21d4b4fab94d35ff5185af893ae69ac14ce90f21617a402e7493fe591fd72df77a44b3efda3fa3b4903a3b64dca131227958dea104b1f7d7ef14af505b84134c918393e435d4c30fa66d7d761e8a30d86b1653f88650d4735fe45b8d816780002a4775e908958e5da0f9f14b63e1f7680a8964e2ae54106a541df52f1eda07a629998bee290929757f31cb6d9476631ea260278540371b7d7c784171f860458957c456e569df62447c33ea9db2767a5635cfb802925539b1b8ba7e0ea0c348a66c80a7eae0daedd1ba49dc015c668b990b1b758c306b108bf05c64274cf12ef0cc3150be8819b1037d4019f1c54c6be876b802fd11825fb236665b1778ea14af4a7a6a6c9bda6550d105463f154f244962a7a4ec6472b691ffed51fd3e975ef7f31e83e57c4a685d75b72b5c1d512f6078be28a48803c78afd62e9d534c025cb25ec2b5d9578374ab15f7c60bfaf4aec9bcd4bc25f10df039a67b1a1bd4141d9bd41ac40cfaf51b59778132096a84d784d30fa5e33093bb79d80c71e080a165641c26e955b8640f92db7e9731341b8c713846d4ac591fb1ba8f8dcb512730039aca8fdd6f3e9723bc265bf91244e138516407ad8f53c8b4065c88c0cbf78df3026b14796c7c2f139ec4cf85fe73ea3e0f2775703ff3ee849248aba3b5707a6820a2135dfb825e2aa276fd1c149fa7fe4af88993542751339a48d11445ee55b6a32208a730e2c834415b386de71ec378b98120c1b330dd39cc8337e96a73f7c7844137014a7e2a10718f46ab7fb8ba3d29f9b3fa705a22d6430e41578a690ee600b0657e6d4744abdc19b96156f0fb3e9e98ee1156afe63cc29b262cff9e61b11bda1275dd6518c49a59ad8507640637c167c1599ba26a27a2d7fdffaba97a0d13576675ab5cb07f269ef8a5b38abeb6ae455cf5a9726a64a816e0c1385810244219aae8ae4f7ae86ec1caeb196d45efb88ee2139c37bfea989c2a91b3d186cc9cd2197d100a8287e258a8c2b73120a20ed238c5c01f405c380a52aeb986ddf97d4a6d34c73e407bc64a09c4bdd7e0e718467457b9131954b2bb159bdb51522eff5ccbbee2d409a2e2dfd732b601b2ba505cb41793bda9a33884fdd115d35c45a48111b7dc902839b42c69613b57834418544c416689aee5f8659e281b803211fd6ad0877fd361805e767daceed85aa3833f59853fd28f90576debe501ab41852e5e3143f0c58805b7cdf535e62ce7f1db75858e0e786e01baff337db1306e84d71d5f6c43e05ea4c6e5ebdcb3f460166e22defe5b0d975baf9aa5f09abeaa8992f084592b76a4e252abfb60aaab461a2a3a88df13a073e93ccf92d20e513666a8a937f9cfcb74a96b1890a56407450c79d2662f5f2904c1cae926302164ffd798c307ba4df55f3f3ce5a7a972495785953fbf4bfdc41e4ab3a1a1955480bf1247dd0db6ba2f07f47f0809a3856c79b1677f0724b8c7690964120f508da9f55af518efadaeeda4a679ba9f1cbcfee11734a4fd0170f58a8e526315ea4789ae86f6d52b643d524eb6a944ce5f9b68bf49686024e25b4f04382fcea134de1a6bf7e5f743fe1b1d6baa89f29a7f62b245cef0105615dc9b3a60078072f37fa978006052019ad457046130978b84f2b7471c8ba874339bd2400541b993f4e735a39d6ca2cc87a85184ff89b97fbf1cdc4df7517cf9abbbf227a0488293be08401ead1c9c70bbc3ebfb33778948e99df0bae1dfaf6f2d3ac2bbf97d253bca3d70d297a4226eb7968f7f717c47fe07a7253dea77469f0ce3203ea8dab76371356f58ae1b0a95bf5683eb1411922a04dc700298abe1d191a6d2a211ac663bbc636bd5bbf6b16cc5b8c141eba5b6c176341bfe621405d04ac625b0ce3d74ac879b58c9048ceaf1a3cce8d04f03eeec697bf727b638ffc296c45f285cdad397cd3c6db505e01725c5c12ee7b6a68f5dd3592770271383bb69c6609d0438357967f84d6ff8c04b29484e2ceeb53055dfab1f24e6eb24847d6cccdbe92dd99ab77b87b95817d73b526fb3dda692adbf0d5a1db4a4d478717572e8975a8822109dc3c197c543298feaa1c1e9a68a73b0726c6681b25069f0590980fe41629f6a89ba96d6638dd26617a9071f60ff3ca4c47e4695380c8079588e6d7a66442e99db959dd2510fdde330b80635e2dcf9d2c8cd7b165daf85e75feaa377ab5f650edf92689726e43ad1802f08b1e3aa4fa95ee01e386bf63cf07ef14415397c3230fa45e1c68cc52399d598287e31391cd0bdd6fb17cbf235a4c116944527d3197c1edf8802957f8a741cc66a406db301eb51358aa5ef8300d36d309acc935bd0af08580b8f552e11c3f5e517cce64a9f07592635bbf0db293e071a7d49ab7c45216ae9464125d7a2f48fc67db50e8c776bb2256683e33dd5fd16ae66405dd41c1dafe3c0cf77e8550735200bd49e13e9b7b52dc08b941ef82180824748cac2521ac0e52199dffc76ffb8bc60ad24c5f85c2867ef0d4a76689e39fad830f7cc0a82664aecc1abc42af491e8d80733c51eb5eb1185068ce8312b869f3d39ea5dc0b7f5d96cfd4d708fd10187aa46930df63e15fe27fc816fc110277965d7e3e58245c3bbd19cca82a04303375aa4cfc49238a9891d6ef65d8f2230b2fe0bb6fc0b34c4e3f556ab081f1aaff10230f46b5eebc7adc33f7ab041f84f08ae83699a47127f55ffa3465e8ca346bd2619e631c60a63cb10688d09a4fe5197f5f599c106f9b8ea66d631f7dc010282dad5272c5161e08cfbc5d5892e3059a9798c35580ca212bd2b32be859222e31d007592838b8ce947deb757c0de57d7bea5813b42ee79e460310e46c14576b29a5622f2b5592fb5d3a3d24e1e0f3eb60409719702d44b1520d42729db2683148434ea51a731e81e619c75635a8cc77f35e9596c277b72a7d2a52b15f26397abc3b1ba0f8bc8e816e64176fb19b92ab14d26de5da6cd06e6ad619800367850ef645dcf9115bb053c8838594a4745ea9409b89e7cc6ef0f24174ef647563e8d5a02e52ffc29ccb072386818d0b46e2052de56278b524c86986073ecb41b8db43046c4dec91b0afcbaeeb4a551d476b8a7ee9aa907ff9aaa0cd2deb4340000cb9195760dd5a6defbc679c3322c26bea3db6a0f1918c5a03bffd2158fafe63ba96dc7335bfeeaaaf262fc04c119ba171e17e1930dfcb1471c8c0a3b4c69853183831214e4c9b10d53a116e830db5a635fb1abebe10c1b7e5e46e7d0a2b15228ea37cf14d75ebc188ee9c380c3e5d9ba7bbbd68edda74c779a27b9f1fafb0ceb0b1d0bd63a67c2d0729a4612f8e33547a73c42eb69c2e87ab730cc04b4d7a9204c39a108847dbacc5b05091cca2e6b19f65cdb8a780481b9cfe78ccc1b6392d87762d8189a267e58043f95e0d948d8a0c2a27c098bb1fe2247b5fb3d25b9b108a2885b7d2a687a37e2251db71a7dd8523350097b8d0ed83a3bc08f80934380c3b4fc955be3f8571e447de3a4459e0e596bafae2ecce2afb1826360b791140ea029859cf9878a2203f68797f310f6e4330a75c0dad3a94ceacc0c25695832ee128b362feeeeb162b003c0bb6efa50ca852e9f2ccf24b48530f695b1a4866456b03ad6991a4638c94b1a2151ccf6476e6fcdaa40a161d54b39e99f5c6efacc0456c2a7274bc0540efb2afacf87973919e7c125bddf317dfab4eabdb1f060e4ca9e31d9fb7afd3d731c1ba2f733613ca956558f5524155242eb9abe67edbb38f496757096d8711a8183a81eacc2d3dc22b83fe3ab1153c74ff1117028d73f2066ce21e15abd27c69117c149e4e40ac1fc376e760901f56b4024e1abaaa5ffaa86fb7853bb4e1d2e5b87bb54cd8f60cdc85e10218aebd0bd80c15c09d4d0bab953e88a92720d8450cbc5c279ca4c87809289fa2e25a04a69d4d1abe0d94f7404a7336336b5164571224784d3c7ff9de84565c92154fe62d85244c6ea7004a8a3135295d90f0a35a196dc55d674192dc4b2f877384eaff99fe418f82f018bab52aa9b9f8d19db75bcbdf49f6d2a7c157551077f492a1107327fa5bd5846b2c4b04b48f05e2577f280ee3d59e9af77e8b6789eb5606227db118102b52e534ef3dd31f070f70c2acd41bc260141c808a5c05596217fd9fe5e1e7b902110b9eee6f8fb048e13ccbedbc09d75d72a6c4feecfd13455a60bdb19f40ef4f13ad2c2dacd16e68c9c9b5692105aa50cebabc173c3d5f44435a413fbe64457a28d11d76948d164ae0f359f38999d0ed8a720c528169cbf9683390f68bebadce765966d8c401009b8085ff8d620322b94ecc27e32c47e36f761a8e7c6e86dda5313ceaf964dd317b89fab8a1816c477905f933ec95971fd5e1aba4f8ba571d544c86b7a81aae17bfc26a401d2631b7b4ccdb4ed0307023f29dead543384f9f07cd88d60c9a7838376e10745bfd0bd6a8b3c93b1514763bcaac80b787af5f4a491120fca0955bf5a7bf974a30e77599a1495613852d7eb874ec0df1dc11d69e2a63bab0994c81bd477117c61f86ab78311dbfc6e4194ca1135827a84a120ceab54990c69f9591205eb2b2a96256fc05301b2858f1a49371bdeabae0b2157740d6a2826d0e1bd6c3e6795ea3c940dfb521bdb67cd7f9bce13eebe8ff908bc8721805db0923fb7c050074fe00f50896e9dd9783eb984d652889b0dafe7a8a0c9d08ba17c729fcadf6fbf8723af6f85e92a3f27d0aac2649585e082e1790451f8933e280d0942a1de11f664a23641843ce6cd8e2649e09ef00081d00f799950764a17e6346e102b771005f99e2cff289a42e37bb446219a34bac78c86d42a0567e1cd226daad8e5601bde46d8bbd0b67c5784e2f1cafa940158c825aeee17314b51fc57af9c40e08afb943866d3420a5c7a6822bd5c3ba2fb311c030032f3bc28452343d908a10b59122d48822b087651eb95bf043d864f6a80659dd435cb2d372529882fc1098c746b7cfac2256ad06d7545858e68112537bccf6eaef9a1ee815c3efcf890fd0ece4dac5238c271be83fb51d8f680d4075c39a760ac1a503bbfb4144d62ea719a7c361a83075bc11469bcdc81b705fef2b5b24745a07750a6094df45215c7f78d5f644f35be40a43d4d0e465e19350cfe56117ac62162fe1b453f71e43d27f23438e792b967be9d859ca38cb4905a15214b3e06d15165c77705211a579fcd8e8f675a4cd0d604f9666f99ff459012c3ba2b2f26b11f6c2d27bd4a2024b56e7863f44d8b2ca242cbb6e47b2f8269b789575bb8393d2d4bdf8f613628db9aba884d5b5b91a900086818611efeb1618d651bbeb9aa3c520587b23f5461ca38cfa8033b11ce484b7f4bb7b9482a967619a849852824cd3d1b508c5bf3ceaef3fed359291430c0674df230e96bf11c24dd0c952ee7bb07d5e18a7b5b7bd962b4c6c9522eecffdf1a2e33507855918db8ed0509f428a22045195f69d8fa5f0f260849db20f91f633e1e30aa1147cf0392f86a8506d5c9c0461bb08a2284342df0a9e720cf52aacc5dd2b8bd0bcb87c3b61d1cc4eda9cbc5a38923c1075d25b5db295277e8654044780107e713d53053f66acf66b2573b122d93e3c910641b96566d3fffd61686f523d2b16c0de4b2ee83e5b033c8aa391b77c818ac2ccad2015cab3fd444707afd5ad342d9bc84d82d0fd68066b8e6eba7078851136fa614f3d5052ff0aeeb9b40aa58feb15b80b625bc44a930c8e11b56bda7e5090e9c9ab936c9b906a7da05484771b4e7f624cc7a1bc207d32a18a4a290aee5b7a83ea0ab4576a790f805c14e29948953f61f3114ad8b63aa9152de8020c7e00e320a3c0ba06d8115b771695751e7069d3f31e6379b3b3f84a8aa76311b850ee59564af5b018b57f17d28264c2c14f0d7da69ee4e4947003ea7dfb122aae202008a5f70f7c2f2ca0ef75bbbf1557ad63ec30c5940d989b3475b8b1ffe562118aaa2cdf393f17b0b661a133ef9bb6a0f73ec6aa66ea2249f675923db9499b9dad7d16acfb61c3c67b4035fde340e430d2fc6eaecb5e7604cc4bc29e614562682e81948daa8000094981e74d607ff080dbc10f3fde7c035224c67efdc4b419adff7c273986bf937bcd74f39d490d13da84829e79356760cdeb19aa9a30745c653bc3942f52487ec4a00e1967bbbdcc72ff81a293d3f1c2ae7c8d31886f4329a9d0beb75682a2a3b37b3eaeada4c38be7c807ed07c0acb7ef9e8fcbdbb155013440bfab7847942979aba8273c5056a58c0f00404f2e8f4dea86cd43e1923afeb13acd1dea29d07faeeeda57a05ea18398d958cc6864bce23437dd658918bbcd7838da12b3a10839782586b6c2db9a200718d1508ddbe2c4f0d842d35042a72d8c37b58490f4d24d6b6ad3d13475e6fa91619017065c8ae63510c6990f1ee155dfeacc44e9e74f81f0fd9781b9571224f6439b62da97dbc3400d036b8af878714b522508933a791aed0cfb0fb370dffcde2704e8cde517e99b0dbb85197561a7114b4f40f3257018f5077739a4f7a2065bb91f6ed12b74a22963b607eb2e35e4c8caf2104e482ad98bf8b62276597db4f9b8aeb855b3f2a4ca44aadf3e8726ac47a24a23407914c0bbd0f6d7909a3c5f1766bc073d8258678fcb6075a60a1a244993832baeaec210751cf53f45417cac37288b1ef406bf43113da7827f8165c1943c8277c35afd56e8ca604b8c5c7ec2b819cbe76ef79c697340354157e639e40908ed6d200d79024dc285735c364c1e3748cfdfb36c265f69e81c2b0e9f1ac13868eb9ba97cc8465aedb912e57c83107f0f7bd3e07df1bc05c1f54db305094eae136d239a0558c9a7a5ce6a9fc9497812a82d9177ef4cba90d5b95301583cb1be4ef73450dd358b17d984b8d0704f7ef0e7d42e40bbee26ce933aeaf0e27b5aaddd1e70c7cf050a45d0fd7b4098d19ae282d8db986d8a21865e867d2a27f535d681ea1ca1ef14b9a017a20b428679d82e26d3df6c8cfef109ce8a7bf721706ee5feddc5c9dc1844b9f10be84cce479b1c972fe965dd78613ad75ebe208107a4641f5881c98f1694b410b89335436464e7b266eb3c43492d38eecb11adb5d72558552b4e397dbff61b678aeb7648569676097e3e88fb9292a3d04027db42bd207b66716d6535a892f18b909c939e540bf8cc048013a18ab95d2cd17f543e8210f36cb2ae002b8de69ff605965421a28d706b33b9994c81a2dd66c61bd5161100a971b283e5d987d687cd846bedb86bc06d5101ec9add64f50a0925420eb3e19fc438ad671184082fb9d8281e89e606319970653f6825a50f9a6398c01c2459461e456bd404c03a9b7b47ac3333d16532a9021e7ff91f1fe111d400d9c2da8c6012ac88cd0b823c511f524d95a7b8f4cae4642995425105acf81e9ce55262bd120f29e2bb0df45f1d5fa6cfc0aed9fc47f707c55931130fa3173885b8da4d60ecb52554984c6916ec3f893df547422bf76991b1e78f1b66c894e79aa400fb27b52bf8e720fcfd1abf0e245ac453b15623b6380e753e47190486376a92bb8cd12571233e6e194dcba6a8285669b954497437bd765debe8fadf73c53619dec25f2797ee41eabc9e6a27d014e1fc21fe6c29ffe88d1faadf176d6b9a23b8addadf1fa66807991f01f27fe2279b02d2b8c0b52fe4bcce37e6a732deefe1f3a8c57ae4b3854f0653de216fedd847386679cdf97cdbb12f81aa3b11776a7a2a281e3ff7cc06c225f0da9e18b06e5e6906dffe00bd05ae61ad0cf65f324385310bf940f78d1e941e22554ce79ca1884cb8f9efb9276dd2db60b1d2992943d2ddf33d3a54c618110ca22ffab49f64e601882827332a1a932c86f4f23378a5a09b8b5be53b758ee60898b36c90224f010e599c43a8fb1dbe5153f9884a43654bdccbb5b000c389b14d2e22f58182f8110f1c3d584056f9d3a0da2109be4bbfe4c1507708ad2a4ac974b900e7ab52e25cfc10ba4f507ae5604fd5a76dceb1fef5498120be971e8002d3fd7f57c6fc8d2b83ca34ee85fdf7a4f7064ebe01faa1bd4f0e61f98d6ac8548c9262665d3e02a5b3b51ff772344908a6dec2da8de321b39e5b149457aabd9b144a93ba139f1f576b5c1719e0df542da341c5de47964cb9b16311b17129fc3fd9c6c2edde02f4aaa5f665cbfc4d28358e11b003a44be443bc1206eb7333fec420c2558394e28170ec7a182b3e3172b54bd32aa5a329a8dafd9149452f91af2152fe143e3e5365456245594297c40bb69b7f1fac1e1775b4ae4bbba19379a77dc3c30bfd741ec5903283211dcd90aca9d5ac25666ec19b206d834dab99485f0aefc02bb3d3ae78344daf4b823e8873026bdb28cda31b9f8ec14c13368fe5a17703214f74b73a3aba5cb3960109f89bae8549fb7b24a4a0b36a437f5d57ebc36add38f7ca8f63b1cbd61e0a4f23c0de6486447eda0fd583a9e4e8d8619adeb03793fbe21ba4b5cd865a917b068c016828cea4fee9ebe09c9a23b20f0bccb9bf092278e4ee7da81b24d0f0f9c75ced0f4a00e991de7c66ab2b7f42e3b684f525776bebde4c9679cfebb535c1b31b0b4be74d8f9baee111102a2fffd95f47d4e863a46eb2b70bb9ec0cee266ed5d76ae4ad2acc7cfcbbca6eaee1d0abc0501d77d1fd32657c1f4a7ce82aa937aee1fe25071f2fc7ce8ef0ecc13643ef3651e431344dde1115b26c051c9754558fdad0607b7a91a11aaa9871e4f640be67e59d8d52ec8438c7fed405e9cb969b3d5e5c7ec29510809acb42c406c3ce02461d6c8d52b1760a540febf3f9aa130d26e7d08b9d8b8ffa5e8bb8b62a5099a6035c46757c91edc02a8555f229f70bc7f18dd3c52f4d9c97c01004962e63e2f212f48cabc25e28059955072525f0be80a9d123b3704ab3ac83dc3c7034e2c84f4be2cc61f2e297a95648f854e24cbfeca80912419d7770cf429555721d9857acb7a2778b00ad28408b1769c623cedc0417df6e5cd2ebeb90f49673fc3cc02e12d033703746f57fc0d9e4ee4347eaab4f4119d89f0ed9d18b830bfb870df2b4ef5a1eae43f62170d2bf7fcad26cd18ba363709d6ebdbc41791e856c83f400ea859cb9a0398b7a20a92df3077b6c68b6582d8712d564c9e102af9bd088ac2ebb52563c79b648cdb99e7b886e49d3538c04a760d2f4a392347dd37d457bff268462054a2a9257c2967416b570d622d01c411331a8c254dac6d73ab911c7baab59b360172d115b9c1f1056297a2e4b47bef9ee85d7c727643f2144d06366401b65f87b8f621c81e4259e985e4e3fb8f530913ca338fcbe6974dcbd54184323c9dca7d3e42622cf3790b7d99e9011921ed7cfc8d579733a37e095f3b380ac8722b002f324ccb90d490d3ea4f2c30ca8a3c01644e7d1d5000a57f83478f2d7bd03d74ef70cf6e42087c2b23be24b2c2c1faa82279e5fe2c87f6fa0cd61ce98e7636949d1aa81090e112c1b0fb6d66c6297eda36f55d24725f6b9562e2b33a02e8bc7afa60c13097eb7220b5a5506ce2a50192ccf1350f79327214a75fa999c0ecee609d826ab5a97e66c9443afd762efb1f0fc1ba7f53f2b5585b976d53b54af0bf5f2fb7cc669f4d3dd50fee89bc01ce7daf53abe97ddb18b07fa9f34bc0a25a42bd138eff17a9ec516c803ad5a46e0f4817def9a7225454debf84c06b003d847cf39b0cf96707954f64097361b69a7d25557a024ef935b0e732d842a74237c96401c980425e02bfa297e2d415c4ed92475ad4ea127ed8d655553932d7c28efea052eec7616cb20c910f7d0df98b0c757afd1c5e58291113bba879c28cf28b1ac3cc744cfea19cb0f8a6738d48d68ab5249a55a98d20e1f036dbd4ed41c85691d476e2abf8c7f1f64f966251c28b1a257bcf46699eee99aa01547ac31b6da85f9d42b1a16bd5c61ba3c829d8867e57647f268633d650597e4f3ba8d4a9adb6b519a4022468c62ce263e5fbd63cb27622bfb460bed68ec2124e5bed256aff96bbe570ac1729e0878ab1e0828e330d1fde30934f4fbe7e866c31a275be553c899f2872a39d40b5e6582bd2a6b684822e30a099b10dd9222f037ab47b6b63c69aabc4fefed9f971f5e34740cac5aab966371370c0e489b16382ac7349be4cc9580d2ded4c141b36a3b6303d8402ea237d9756afe6b664e5c17b202238609863ea15750daa4262c23ac1418573df4593daadf50a4f76e5b72892ac04fa2d1f1e91971a2f1e0f5ee8f9809ee14242b29a718bfe9875c2d8bfa7042ee88a15862ed47dfe936beb8774bf4cf75bd8e6ee69fa00632d80d0d6c0f7808ce923b781843693bac28b641d0a99de4e4720a47494a6dd8ce983f1e31309a390c27e16fb5381a7d4a5aba5ca348d4a3e5859d2c5cfa8c6e0819aca807edb578c2f3f2a00d4f5946e9da2fcaefe3215b52e1adf74452b60740b23f0c65ddee1e896cb14dee3db85cc521b7d4bc64184791c230fe03c53cf9f10d07fd6c50c00d13e2b544561f4b63d8fc42618ccce52cec3e44e005648ac8ba7167264e7fbf05204d0c8e19df80ebde66d2c51fa6073820d2712a921aba9cdcfd6c3673281c799362bfebca0003acbbb5c8b0986beb5ecdd5db453b1e1a35a82779a2f94d2d79f1aa36b04307bb4d77b3100e567f860cf3fba43a06dd3180d8e8ad31b8126dc9da21be7c05d80e680c1998c9f514d3e0db96e37dcd0616e26eff92eefe54159c3e8f9e4a2f5b1426f132f2087d7e77b230f0b6a713b12fa07ca633a0363a9adfe7309f183f0d37474034bb136d42ac4d38ae776cb6707650a1d8ee1d083e54e9f53ecdf574a3f53eab2b44a24f8906ad8060945c1c6388c50d1796002fccfe136175c3d37ee0c635dcbb1c238909e53285ad15c3ae89fd2bdfe9233bb966773fb81b1aef51c632ba46622917447f5838c7ab4cf91fad4799ac1ce370aabb073ccfad666a8e67d496ceaa8c0e7a6fc4003846faefbceb8085ef6ace1b082733297af60fbb9ff049cdfe48ad573b7b5cc585da108bf50e057c7abae023ce2cb328a4db416023c876e658e35a1420ae7daea92dcfac3946ad3c725f94703ce817bf5582697a63c2be60aaa94702a6b6381cd417624e3b8190d0a363db0629fe44b24b545021c5c72894abc2afda1f5ba416549f063f4555df4bf879a15763d3471f183e77cad4f449f46d68edf4cdef716405397e1f0ce95c6f83aa7a1d84626382af40eb6582fb4c42196db7f43923a86f3e364d8b0936d1cc5a3eafa8c347db45dd6919be31631eedaa207e0beb16b9a2e9a187f7da08dd0fb57c73ab12cd87d4ad42927793307a822822ce0d525725560949889300fc4b31dd19336c1b27fcd9c32ace6daed82443798f246c228f3c0e78e53f2cc1b40f3cd3fd781d9a7ef8339fd04c694860c5d30e5e983656d44698631051b3772f90322adc33310a83b04fc8cdca9df12c42bf1e88ab482c69f5023fa235f8c82ff26391fb4516ffc34b53b9f69779ec1b0e347d16b6cdc2673b069c8000ed414a302e81d637937fb971d84b877530a5a2e1d15757bc1705da7130ca4506af243c7bfa69a250fa991f68feb285b9c4dabd9ac217193d95a8d7e05a8c2987bd8fe7cd27d387fe916ecbc5fee3259927e42e28db8b488922689e5a2cd53fa0cdacbdf762c5c430227edc941c7e1a31c51aff2db2ecf513d36ae788179fcaeea89dcd63b0ae7c79911e4315eacb3bf51ddd28c4ba614079d223e9645d83af3295669da12fce71dc2da5a1ebe00a9c23037866350deb01483b232c7ee0033442ae00702005af627fad90341a12c52d56538477ed73c31eb6cd0b75e54ba9b7f79354b611c59ddbbc9a9ec1b25b2647b4e72499037268cc773da70384d486d19e910dc7c6f6c9b487f6605a3f0d9c930aa843b3c812fef80c82b9fe2f253f5e4f54299b02b238565641fb89bfbf265341c711953ffcf86b9b3fd85de2fc090c7e6c42228ff87cd01a16c8b5534831c08c2cccb2b387b05992c87282658dfcfb83c7c73dc07fa9193faed47265de8ecbfed98c72ae3be676ee96bf2f85922647a6b15f1df1dfc2738205284f0a411f7479e3b3302762481497d5c8c4aba7462d0722cc13a3800afc26020e70f3cb69823cc2b3fc3223a36564c26aec5a5af1b9bb9697985a9fa3775dcd26b726ec762a44f786877fb14cccfb33b70f1be33e299460bf7aeb7c38e84ec4af0b45c53ac5823f159cfdac70b1c99de4bb979a9348cd630355f2c85b2e477943cdd21dc4be6c97febfadbcca8386f03375796e38b9190af11e3f64b7c144364f1092fc12584fbe385342354a7256e3b37848c882465e7913fd1cc272485ab029ddbe2803e6f23952eed97918ece2d1d4875b13d53e52b1ec4f354cb286aa745c49d400f1e81a51ffb446aac4e65fe521a2549338f51a44bac5a12f2871efaa04e32f130e6f62dcb4e0c1fdf227e312af199a81ecd9c1b93c2e4178cbda2c13d2c9750d65e8b221d600be9afb9a794c2e34291ceba0cd2ea2eb11b6fda0476df4cd7072a6564291f0ee26cffbcc09f916f21106656dade79f8450c08b9d39b729414ad335debb75d724be55155265f1f053197f62dc16f9064cb05be553fe4bc513edbd59f1bd75701399093af63577733137ff4e02c6f7ff2feb53e0153b93b65efe0351a02201f71a82cf831cbc486d1d533fc09b18c1f6caad92b29d6b4f9026ce3e6d097436f57ad745d583fcf92ada77efa34a75ad0b4e4f1e1e9aed2626e9923087541e239373f1a12f73e52dea6511ac150af75510315d8b1824c95512bfe92687735817b9f5849ec5a76607bc076b63a00dbd15db67c7163b3d1e69fa829703cbca2ac247cafae5cb08bee7dcfcb62a6b5a335450db13ce4f80eed4ea5d7f39e3c9e2ad722ae03e65e2b8b53ec26e67e528f3f166faa7fc85b835f68c09019bd84174aa978fd3d7519b314a067974e5d15362a0b12db1f8848d9106a576ee45b75f04a8c8aa350a41c22259f91c51ca4ca65a52e3e0750b63c5f3290aa76681d8a53f86ec847e4d0399f9d2a5907694eb31a8ce841a5aae4c222f43838e4da8c0c807cf825a4cb13f2c4e894c50f2f0406c89b25f0ecf77a0ddea2748ea33092b9170a2a0ff5be3127755e2f76610acc89bc73eb41503690330c63f7374b276740bc3fa9e754647cce0aa98b402ae3f3511c7933a8f260ce9add5ee5f8183e6e7a1d85c032a672de7320489d52158c34056a6ca3532b74eebd4e6f2c82e8c5f088b26527de9f1b8b736cb3f6f0dfb95e5faf9de952d62338dae791ccaae3ad46082c35f4d359922148e7ded7868b6345e720587ac141d3fede5ee8031437103522529de4ecbd8b43ea0c960c11958ddd36be224c24fd090d1e80bf815f0b9c5ce7c3ec93ccd26a350b8fbc9e067c3ac650683ad05727cf26fc35ed8fec907925120be983de747d49ce068275284bfd3aba3ad28ecdfd1073f0e85e72eb0262c8688e350d10724a6022fb232b804bbdd2593eb52b2b62901683e9290d6c825ab5632dcb44c9040721a3a07392e34d43dc95ec403faedde0a6e81473c1577e09a075aac492fcd8fdd01341e6be9af45de4a960b52aeb8115da0136d6cf40864ffb8393bd608430cd430ecb0c24bacce8c073fb4262c7284860ebcebdd0f812ff260e5bc38dca97128481c32cb02f3fd35c9a46ff5822fe41cbf07abb2f8a677a7350bf9a5441e6e99f578fba2275b98a40a4e79a16056ecdd4d32a69cb48d41f2de5e542da6347ec0a2a76e019a141d37fe9bd10d52b3f405a1fbd66909e716d1c4deca24e3f089632c5759dfb58ffe989ac053e75d410a8df712451180600e94e728f5be0dd6072be6f4f3a0db80a933ebbe67ae8fca36e7bd1d1e0e464eee50fa1dd839252fcda052bb4fc9588eae02cced4fb8e01455b269cd8a30f5a5b7c56c5259733872ab3154db82b55930c4df6f685801d8d1690ff526430a836adf55deff6cc3c79b28ff18d75998e4dd2d2d18dc32dc04644df9b06dd2c4f11a1f4d10a9dcbf08d5e0f5c5c2d8132c5de7a097946e97549533c3d928079039610d8d1ad69b8929a40fbe1d2fe29a40521204cb16af4af8f86dce9652ac5bf74830c60091eeebbd097cb6eb587706ac9ba7bf200624258f3f2150f724746389684c8bbc092ef092dfad2a7a2cabdc953754ab77055da8f12746c23b9f4c5bc1c2a94cca88ed52bbd459b3e8fbe960c3899abc46077b0d79cbd87c5ec3a06d0b6e0562237418843e14faaa5534ba6bc1f0f7077a478a10b2c062c519d62a6fb64f105206b31281517b29086f57a576b8ac96f535d48b5e8312555cb4fd7444b8686c79853b2e85a24d7d652b97e448d81b167723e7d8a96ded9e3a776f88a078a1ca4c2daa85638439f0c9dc18a12ec9c72d47482fd0c0f84a2226849913dfca847cb5d630fabdde800d2448c6b00fc99913b160e49fdd333a651151dea239c68201c0cd82be57cc708184664ed17a14babfa3453bcb35e2f570b2e35c3e69d72deee73fef64a575517ef14b9ba5867e656ced1287ada7cd80016eab289c4544f12712978609112029274397f373a649568f04ab7148480a5237f897f7d426c75adece54127df514ba3071dfffb9c70de71edf70d495d49c0c8dbbbbaa63fdae986b8bf94f23506f516f1bd3b6ef26aca1a968f0fd0c68b5f497ec1ccbadef339cdbf659a8cc3c2dc2b9e4ceb9fd1e3e67b6734a1527a7f344d850386a46dcb1aae8fde7b55ec351c5c25d6163a0eb639edd5d8264699dd5ccf61d9f4e3111199fd8478719c18411d16fa7c291774271789c2d7df5b4866ee61839947b7cde84791e5e3b85689b17e6da70bc1061ae2c8f373f570f1d0d7ed654926c9e2cc35d186eef104e3df101010c97912fb56ee2f31bb235379782d502cba0090e810ab8fbb4b4865860ce809c0613806555a308cad1ef7005325a5621a8d9c8253ca715dfebc9aaad9c33fd1db6aa891f0887099644d2fd81ff3c6df806e650de0730cf81ebc13768cc18ae7da3ccefc644414bd6495e580d6517ca68ca1c985d9a137bea08884170ff31dfe6a78350e0aa30da6d8c838b480bfb9d6f15328d605f01227051693873a0dcf2654df6e37643a6e987d3caca7bd977496bb06ab6e42bb56ba9a2982d70fe69832c08cba392bbc6320ed56fd0f78ef93e4e4d7c21ac59a35a41230fce3d3f6847334e0d7692992a436e39f39654ab71f61e81dba1ba59df38fd0e4580993797d5582f4f14f9ef5b01a4f6886919eaaad391c83b0c132d1298f16d50cb99ac8f3c5e3bf21c7639927d79c2c8fe229010d09b5b71d14860b12f8456f01688268347b16aaac22543bedf41f74c2dbb7e479da17fa79359b24bff48e01b0e42f431a5c27c7ee1fbb5ebb2f6b8604bdab783c5cf69838ee31e7aef1ffc00160db945904ac8868247422bcad224","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"643649ba80ed23fdeeac84c02c742703"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>
