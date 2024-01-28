import crypto from "crypto";
import fs from "fs";

// データの暗号化オプションを統一
const cryptoOption = {
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256'
}

// RSAのキーペア作成
export function generateRSAkey(keySize: number = 2048) {
  const key = crypto.generateKeyPairSync("rsa", {
    modulusLength: keySize,
  });
  return key;
}

// データの暗号化
export function encryptData(data: any) {
  try {
    const serverKey = fs.readFileSync("./rsa.pub", "utf-8");
    const encryptOptions = {
      ...cryptoOption,
      key: serverKey
    };
    return crypto.publicEncrypt(
      encryptOptions,
      Buffer.from(JSON.stringify(data))
    );
  } catch (e: any) {
    if (e.errno === -4058) throw Error("パブリックキーが見当たりません。")
    throw Error(e)
  }
}

// データの復号化
export function decryptData(privateKey: crypto.KeyObject, data: Buffer) {
  return crypto.privateDecrypt({
    ...cryptoOption,
    key: privateKey
  }, data)
}

// RSAキーペアのファイル作成
export function saveRSAkey(key: crypto.KeyPairKeyObjectResult) {
  const publicKey = key.publicKey.export({
    type: "spki",
    format: "pem",
  });
  const privateKey = key.privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
  fs.writeFile("./rsa.pub", publicKey, (err) => console.error(err));
  fs.writeFile("./rsa.pri", privateKey, (err) => console.error(err));
}
