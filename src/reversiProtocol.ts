import net from "net";
import { decryptData, encryptData, generateRSAkey } from "./utils/rsa";

const host = process.env.SERVER_HOST;
const port = process.env.SERVER_PORT;

export default function reversiProtocpl() {
  if (!host || !port) throw new Error("host or port undefined");
  const { privateKey, publicKey } = generateRSAkey();

  function decryptMiddleware(handler: (data: Buffer) => void) {
    return function (data: Buffer) {
      const decriptedData = decryptData(privateKey, data);
      handler(decriptedData)
    };
  }

  return {
    privateKey,
    publicKey,
    decryptMiddleware,
    socket: new Promise<net.Socket>((resolve, reject) => {
      const client = net.createConnection(
        { port: parseInt(port), host: host },
        () => {
          client.write(
            encryptData(
              publicKey.export({
                type: "spki",
                format: "pem",
              })
            )
          );
          resolve(client);
        }
      );
      client.on("error", (err) => {
        console.error("ソケットエラー:", err);
        reject(err);
      });
    }),
  };
}
