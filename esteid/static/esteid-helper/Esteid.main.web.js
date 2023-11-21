(() => {
  // IdCardManager.js
  var LANGUAGE_ET = "EST";
  var LANGUAGE_EN = "ENG";
  var LANGUAGE_RU = "RUS";
  var LANGUAGE_LT = "LIT";
  var LANGUAGES = [LANGUAGE_ET, LANGUAGE_EN, LANGUAGE_RU, LANGUAGE_LT];
  var errorMessages = {
    user_cancel: {
      [LANGUAGE_ET]: "Allkirjastamine katkestati",
      [LANGUAGE_EN]: "Signing was cancelled",
      [LANGUAGE_LT]: "Pasira\u0161ymas nutrauktas",
      [LANGUAGE_RU]: "\u041F\u043E\u0434\u043F\u0438\u0441\u044C \u0431\u044B\u043B\u0430 \u043E\u0442\u043C\u0435\u043D\u0435\u043D\u0430"
    },
    no_certificates: {
      [LANGUAGE_ET]: "Sertifikaate ei leitud",
      [LANGUAGE_EN]: "Certificate not found",
      [LANGUAGE_LT]: "Nerastas sertifikatas",
      [LANGUAGE_RU]: "\u0421\u0435\u0440\u0442\u0438\u0444\u0438\u043A\u0430\u0442 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D"
    },
    invalid_argument: {
      [LANGUAGE_ET]: "Vigane sertifikaadi identifikaator",
      [LANGUAGE_EN]: "Invalid certificate identifier",
      [LANGUAGE_LT]: "Neteisingas sertifikato identifikatorius",
      [LANGUAGE_RU]: "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0442\u043E\u0440 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043A\u0430\u0442\u0430"
    },
    no_implementation: {
      [LANGUAGE_ET]: "Vajalik tarkvara on puudu",
      [LANGUAGE_EN]: "Unable to find software",
      [LANGUAGE_LT]: "Nerasta programin\u0117s \u012Franga",
      [LANGUAGE_RU]: "\u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043D\u0435\u043E\u0431\u0445\u043E\u0434\u0438\u043C\u043E\u0435 \u043F\u0440\u043E\u0433\u0440\u0430\u043C\u043C\u043D\u043E\u0435 \u043E\u0431\u0435\u0441\u043F\u0435\u0447\u0435\u043D\u0438\u0435"
    },
    version_mismatch: {
      [LANGUAGE_ET]: "Allkirjastamise tarkvara ja brauseri laienduse versioonid ei \xFChti. Palun uuendage oma id-kaardi tarkvara.",
      [LANGUAGE_EN]: "The versions of the signing software and browser extension do not match. Please update your ID card software.",
      [LANGUAGE_LT]: "Parakst\u012B\u0161anas programmas un p\u0101rl\u016Bka papla\u0161in\u0101juma versijas nesakr\u012Bt. L\u016Bdzu, atjauniniet savu ID kartes programmat\u016Bru.",
      [LANGUAGE_RU]: "\u0412\u0435\u0440\u0441\u0438\u0438 \u043F\u0440\u043E\u0433\u0440\u0430\u043C\u043C\u044B \u0434\u043B\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u0430\u043D\u0438\u044F \u0438 \u0440\u0430\u0441\u0448\u0438\u0440\u0435\u043D\u0438\u044F \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430 \u043D\u0435 \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u044E\u0442. \u041F\u043E\u0436\u0430\u043B\u0443\u0439\u0441\u0442\u0430, \u043E\u0431\u043D\u043E\u0432\u0438\u0442\u0435 \u043F\u0440\u043E\u0433\u0440\u0430\u043C\u043C\u043D\u043E\u0435 \u043E\u0431\u0435\u0441\u043F\u0435\u0447\u0435\u043D\u0438\u0435 \u0434\u043B\u044F \u0432\u0430\u0448\u0435\u0439 \u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u043E\u043D\u043D\u043E\u0439 \u043A\u0430\u0440\u0442\u044B."
    },
    technical_error: {
      [LANGUAGE_ET]: "Tehniline viga",
      [LANGUAGE_EN]: "Technical error",
      [LANGUAGE_LT]: "Technin\u0117 klaida",
      [LANGUAGE_RU]: "\u0422\u0435\u0445\u043D\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u043E\u0448\u0438\u0431\u043A\u0430"
    },
    not_allowed: {
      [LANGUAGE_ET]: "Veebis allkirjastamise k\xE4ivitamine on v\xF5imalik vaid https aadressilt",
      [LANGUAGE_EN]: "Web signing is allowed only from https:// URL",
      [LANGUAGE_LT]: "Web signing is allowed only from https:// URL",
      [LANGUAGE_RU]: "\u041F\u043E\u0434\u043F\u0438\u0441\u044C \u0432 \u0438\u043D\u0442\u0435\u0440\u043D\u0435\u0442\u0435 \u0432\u043E\u0437\u043C\u043E\u0436\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0441 URL-\u043E\u0432, \u043D\u0430\u0447\u0438\u043D\u0430\u044E\u0449\u0438\u0445\u0441\u044F \u0441 https://"
    }
  };
  var IdCardManager = class {
    constructor(language) {
      this.language = language || LANGUAGE_ET;
      this.certificate = null;
      this.supportedSignatureAlgorithms = null;
      this.signatureAlgorithm = null;
    }
    initializeIdCard() {
      return new Promise(function(resolve, reject) {
        if (typeof window.webeid !== "undefined") {
          resolve("web-eid");
        } else if (typeof window.hwcrypto !== "undefined" && window.hwcrypto.use("auto")) {
          resolve("hwcrypto");
        } else {
          reject("Backend selection failed");
        }
      });
    }
    /**
     * Requests the Web-eID browser extension to retrieve the signing certificate of the user with the
     * selected language. The certificate must be sent to the back end for preparing the
     * digital signature container and passed to sign() as the first parameter (hence why we also cache it
     * on the instance).
     *
     * see more - https://github.com/web-eid/web-eid.js#get-signing-certificate
     *
     * Note: SupportedSignatureAlgorithms are available on the instance after the promise resolves.
     *
     * @returns {Promise<String>}
     */
    getCertificate() {
      return new Promise((resolve, reject) => {
        const options = { lang: this.language };
        window.webeid.getSigningCertificate(options).then(
          ({ certificate, supportedSignatureAlgorithms }) => {
            this.certificate = certificate;
            this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
            resolve(certificate);
          },
          (err) => {
            reject(err);
          }
        );
      });
    }
    /**
     * Requests the Web-eID browser extension to sign a document hash. The certificate must be retrieved
     * using getCertificate method above (getSigningCertificate in web-eid) and the hash must be retrieved
     * from the back end creating the container and its nested XML signatures.
     *
     * Returns a LibrarySignResponse object:
     *
     * interface LibrarySignResponse {
     *   // Signature algorithm
     *   signatureAlgorithm: SignatureAlgorithm;
     *
     *   // The base64-encoded signature
     *   signature: string;
     * }
     *
     * The known valid hashFunction values are:
     * SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384 and SHA3-512.
     *
     * see more - https://github.com/web-eid/web-eid.js#get-signing-certificate
     *
     * @param data - base64 encoded hash of the data to be signed
     * @param hashFunction - one of the supported hash functions. Defaults to SHA-256.
     * @returns {Promise<String>}
     */
    signHexData(data, hashFunction = "SHA-256") {
      return new Promise((resolve, reject) => {
        const options = { lang: this.language };
        window.webeid.sign(this.certificate, data, hashFunction, options).then(
          (signResponse) => {
            this.signatureAlgorithm = signResponse.signatureAlgorithm;
            resolve(signResponse.signature);
          },
          (err) => {
            reject(err);
          }
        );
      });
    }
    /**
     * Requests the Web-eID browser extension to authenticate the user. The nonce must be recently retrieved
     *  from the back end. The result contains the Web eID authentication token that must be sent to the
     *  back end for validation.
     *
     * @param {string} nonce - base64 encoded nonce, generated by the back end, at least 256 bits of entropy
     * @param {object} options
     * @param {string} options.lang - ISO 639-1 two-letter language code to specify the Web-eID native application's user interface language
     * @param {number} options.timeout - user interaction timeout in milliseconds. Default: 120000 (2 minutes)
     * @returns {Promise<LibraryAuthenticateResponse>}
     *
     * Ref: https://github.com/web-eid/web-eid.js#authenticate-result
     *
     * interface LibraryAuthenticateResponse {
     *     // base64-encoded DER encoded authentication certificate of the user
     *     unverifiedCertificate: string;
     *
     *     // algorithm used to produce the authentication signature
     *     algorithm:
     *         | "ES256" | "ES384" | "ES512"  // ECDSA
     *         | "PS256" | "PS384" | "PS512"  // RSASSA-PSS
     *         | "RS256" | "RS384" | "RS512"; // RSASSA-PKCS1-v1_5
     *
     *     // base64-encoded signature of the token
     *     signature: string;
     *
     *     // type identifier and version of the token format separated by a colon character.
     *     //  example "web-eid:1.0"
     *     format: string
     *
     *     // URL identifying the name and version of the application that issued the token
     *     //  example "https://web-eid.eu/web-eid-app/releases/2.0.0+0"
     *     appVersion: string;
     */
    authenticate(nonce, options) {
      const authOptions = { lang: this.language, ...options };
      return new Promise((resolve, reject) => {
        return window.webeid.authenticate(nonce, authOptions).then(
          (authResponse) => {
            resolve(authResponse);
          },
          (err) => {
            reject(err);
          }
        );
      });
    }
    /* Language */
    get language() {
      return this._language;
    }
    set language(l) {
      if (LANGUAGES.indexOf(l) !== -1) {
        this._language = l;
      }
    }
    getWebeidErrorMapping(error) {
      const errorCode = (error ? error.code : null) || null;
      switch (errorCode) {
        case "ERR_WEBEID_CONTEXT_INSECURE":
          return "not_allowed";
        case "ERR_WEBEID_ACTION_TIMEOUT":
          return "technical_error";
        case "ERR_WEBEID_USER_CANCELLED":
        case "ERR_WEBEID_USER_TIMEOUT":
          return "user_cancel";
        case "ERR_WEBEID_VERSION_MISMATCH":
        case "ERR_WEBEID_VERSION_INVALID":
          return "version_mismatch";
        case "ERR_WEBEID_EXTENSION_UNAVAILABLE":
        case "ERR_WEBEID_NATIVE_UNAVAILABLE":
          return "no_implementation";
        case "ERR_WEBEID_NATIVE_FATAL": {
          if (error.message.includes("https")) {
            return "not_allowed";
          }
          return "technical_error";
        }
        default:
        case "ERR_WEBEID_UNKNOWN_ERROR":
        case "ERR_WEBEID_NATIVE_INVALID_ARGUMENT":
        case "ERR_WEBEID_ACTION_PENDING":
        case "ERR_WEBEID_MISSING_PARAMETER":
          return "technical_error";
      }
    }
    /* Errors */
    getError(err) {
      let errorCode;
      if (typeof errorMessages[err] === "undefined") {
        errorCode = this.getWebeidErrorMapping(err) || "technical_error";
      } else {
        errorCode = err;
      }
      return { error_code: errorCode, message: errorMessages[errorCode][this.language], raw: err };
    }
  };
  var IdCardManager_default = IdCardManager;

  // IdentificationManager.js
  var request = async (url, data, method = "POST") => {
    const headers = {
      "Content-Type": "application/json"
    };
    let body = null;
    if (method !== "GET") {
      headers["X-CSRFToken"] = data.csrfmiddlewaretoken;
      body = JSON.stringify(data || {});
    }
    try {
      const response = await fetch(url, { method, headers, body });
      const responseText = await response.text();
      try {
        const data2 = JSON.parse(responseText);
        data2.success = data2.status === "success";
        data2.pending = `${response.status}` === "202";
        return {
          data: data2,
          ok: response.ok
        };
      } catch (err) {
        console.log("Failed to parse response as JSON", responseText);
        return {};
      }
    } catch (err) {
      console.log(err);
      return {};
    }
  };
  var IdentificationManager = class {
    constructor({ language, idUrl, mobileIdUrl, smartIdUrl, csrfToken, pollInterval }) {
      this.idCardManager = new IdCardManager_default(language);
      this.idUrl = idUrl;
      this.mobileIdUrl = mobileIdUrl;
      this.smartIdUrl = smartIdUrl;
      this.csrfToken = csrfToken;
      this.language = language;
      this.pollInterval = pollInterval || 3e3;
    }
    checkStatus(endpoint, resolve, reject) {
      const pollInterval = this.pollInterval;
      const csrfmiddlewaretoken = this.csrfToken;
      const doRequest = () => {
        request(endpoint, { csrfmiddlewaretoken }, "PATCH").then(({ ok, data }) => {
          if (ok && data.pending) {
            setTimeout(() => doRequest(), pollInterval);
          } else if (ok && data.success) {
            resolve(data);
          } else {
            reject(data);
          }
        }).catch((err) => {
          console.log("Status error", err);
        });
      };
      return doRequest();
    }
    signWithIdCard() {
      return new Promise((resolve, reject) => {
        this.__signHandleIdCard(resolve, reject);
      });
    }
    signWithMobileId({ idCode, phoneNumber }) {
      return new Promise((resolve, reject) => {
        this.__signHandleMid(idCode, phoneNumber, resolve, reject);
      });
    }
    signWithSmartId({ idCode, country }) {
      return new Promise((resolve, reject) => {
        this.__signHandleSmartid(idCode, country, resolve, reject);
      });
    }
    __signHandleIdCard(resolve, reject) {
      this.idCardManager.initializeIdCard().then(() => {
        this.idCardManager.getCertificate().then((certificate) => {
          request(this.idUrl, {
            csrfmiddlewaretoken: this.csrfToken,
            certificate
          }).then(({ ok, data }) => {
            if (ok && data.success) {
              this.__doSign(data.digest, resolve, reject);
            } else {
              reject(data);
            }
          });
        }, reject);
      }, reject);
    }
    __doSign(dataDigest, resolve, reject) {
      this.idCardManager.signHexData(dataDigest).then((signature) => {
        request(
          this.idUrl,
          {
            csrfmiddlewaretoken: this.csrfToken,
            signature_value: signature
          },
          "PATCH"
        ).then(({ ok, data }) => {
          if (ok && data.success) {
            resolve(data);
          } else {
            reject(data);
          }
        });
      }, reject);
    }
    __signHandleMid(idCode, phoneNumber, resolve, reject) {
      request(this.mobileIdUrl, {
        id_code: idCode,
        phone_number: phoneNumber,
        language: this.language,
        csrfmiddlewaretoken: this.csrfToken
      }).then(({ ok, data }) => {
        if (ok && data.success) {
          resolve(data);
        } else {
          reject(data);
        }
      });
    }
    midStatus() {
      return new Promise((resolve, reject) => {
        this.checkStatus(this.mobileIdUrl, resolve, reject);
      });
    }
    __signHandleSmartid(idCode, country, resolve, reject) {
      request(this.smartIdUrl, {
        id_code: idCode,
        country,
        csrfmiddlewaretoken: this.csrfToken
      }).then(({ ok, data }) => {
        if (ok && data.success) {
          resolve(data);
        } else {
          reject(data);
        }
      });
    }
    smartidStatus() {
      return new Promise((resolve, reject) => {
        this.checkStatus(this.smartIdUrl, resolve, reject);
      });
    }
    authenticateWithIdCard(options) {
      return new Promise((yay, nay) => {
        request(
          this.idUrl,
          {
            csrfmiddlewaretoken: this.csrfToken
          },
          "POST"
        ).then(({ ok, data }) => {
          if (ok && data.pending) {
            return this.idCardManager.initializeIdCard().then(() => {
              return this.idCardManager.authenticate(data.nonce, options || {}).then(
                (result) => {
                  return request(
                    this.idUrl,
                    {
                      csrfmiddlewaretoken: this.csrfToken,
                      ...result
                    },
                    "PATCH"
                  ).then(({ ok: ok2, data: data2 }) => {
                    if (ok2 && data2.success) {
                      yay(data2);
                    } else {
                      nay(data2);
                    }
                  }, nay);
                },
                (error) => {
                  if (error.code === "ERR_WEBEID_USER_CANCELLED") {
                    return request(
                      this.idUrl,
                      {
                        csrfmiddlewaretoken: this.csrfToken
                      },
                      "DELETE"
                    ).then(() => {
                      nay(error);
                    }, nay);
                  } else {
                    nay(error);
                  }
                }
              );
            }, nay);
          } else {
            nay(data);
          }
        });
      });
    }
    getError(err) {
      return this.idCardManager.getError(err);
    }
  };
  var IdentificationManager_default = IdentificationManager;

  // LegacyIdentificationManager.js
  function postForm(url, data) {
    const formData = Object.entries(data).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: formData
    }).then(
      (response) => {
        return response.json().then((data2) => {
          return {
            data: data2,
            ok: response.ok
          };
        });
      },
      (err) => {
        console.log(err);
        return {};
      }
    );
  }
  var LegacyIdentificationManager = class {
    constructor(kwargs) {
      const data = {
        language: null,
        idEndpoints: {
          start: null,
          finish: null,
          finalize: null
        },
        midEndpoints: {
          start: null,
          status: null,
          finalize: null
        },
        smartidEndpoints: {
          start: null,
          status: null,
          finalize: null
        },
        ...kwargs
      };
      this.idCardManager = new IdCardManager_default(data.language);
      this.idEndpoints = data.idEndpoints;
      this.midEndpoints = data.midEndpoints;
      this.smartidEndpoints = data.smartidEndpoints;
    }
    checkStatus(endpoint, extraData, resolve, reject) {
      const doRequest = () => {
        postForm(endpoint, extraData).then(({ ok, data }) => {
          if (ok && data.pending) {
            setTimeout(() => doRequest(), 1e3);
          } else if (ok && data.success) {
            resolve(data);
          } else {
            reject(data);
          }
        });
      };
      return doRequest;
    }
    signWithIdCard(extraData) {
      return new Promise((resolve, reject) => {
        this.__signHandleId(extraData, resolve, reject);
      });
    }
    signWithMobileId(extraData) {
      return new Promise((resolve, reject) => {
        this.__signHandleMid(extraData, resolve, reject);
      });
    }
    signWithSmartId(extraData) {
      return new Promise((resolve, reject) => {
        this.__signHandleSmartid(extraData, resolve, reject);
      });
    }
    sign(signType, extraData) {
      if (signType === LegacyIdentificationManager.SIGN_ID) {
        return this.signWithIdCard(extraData);
      } else if (signType === LegacyIdentificationManager.SIGN_MOBILE) {
        return this.signWithMobileId(extraData);
      } else if (signType === LegacyIdentificationManager.SIGN_SMARTID) {
        return this.signWithSmartId(extraData);
      } else {
        throw new TypeError("LegacyIdentificationManager: Bad signType");
      }
    }
    __signHandleId(extraData, resolve, reject) {
      this.idCardManager.initializeIdCard().then(() => {
        this.idCardManager.getCertificate().then((certificate) => {
          postForm(this.idEndpoints.start, {
            ...extraData,
            certificate
          }).then(({ ok, data }) => {
            if (ok && data.success) {
              this.__doSign(data.digest, extraData, resolve, reject);
            } else {
              reject(data);
            }
          });
        }, reject);
      }, reject);
    }
    __doSign(dataDigest, extraData, resolve, reject) {
      this.idCardManager.signHexData(dataDigest).then((signature) => {
        postForm(this.idEndpoints.finish, {
          ...extraData,
          signature_value: signature
        }).then(({ ok, data }) => {
          if (ok && data.success) {
            resolve(data);
          } else {
            reject(data);
          }
        });
      }, reject);
    }
    __signHandleMid(extraData, resolve, reject) {
      postForm(this.midEndpoints.start, extraData).then(({ ok, data }) => {
        if (ok && data.success) {
          resolve(data);
        } else {
          reject(data);
        }
      });
    }
    midStatus(extraData) {
      return new Promise((resolve, reject) => {
        const checkStatus = this.checkStatus(this.midEndpoints.status, extraData, resolve, reject);
        checkStatus();
      });
    }
    __signHandleSmartid(extraData, resolve, reject) {
      postForm(this.smartidEndpoints.start, extraData).then(({ ok, data }) => {
        if (ok && data.success) {
          resolve(data);
        } else {
          reject(data);
        }
      });
    }
    smartidStatus(extraData) {
      return new Promise((resolve, reject) => {
        const checkStatus = this.checkStatus(this.smartidEndpoints.status, extraData, resolve, reject);
        checkStatus();
      });
    }
    getError(err) {
      return this.idCardManager.getError(err);
    }
  };
  LegacyIdentificationManager.SIGN_ID = "id";
  LegacyIdentificationManager.SIGN_MOBILE = "mid";
  LegacyIdentificationManager.SIGN_SMARTID = "smartid";
  var LegacyIdentificationManager_default = LegacyIdentificationManager;

  // lib.js
  var Languages = {
    ET: LANGUAGE_ET,
    EN: LANGUAGE_EN,
    RU: LANGUAGE_RU,
    LT: LANGUAGE_LT
  };
  var lib_default = {
    IdentificationManager: IdentificationManager_default,
    LegacyIdentificationManager: LegacyIdentificationManager_default,
    Languages
  };

  // global.js
  var globalObject = typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : {};
  globalObject.Esteid = lib_default;
  var global_default = lib_default;
})();
