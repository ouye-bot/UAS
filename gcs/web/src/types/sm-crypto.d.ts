/** sm-crypto 0.5.7 无官方类型声明——本仓使用面最小声明（SM2/SM3/SM4 三个入口）。 */
declare module "sm-crypto" {
  export const sm3: {
    (input: string | number[], options?: { padLen?: number }): string;
  };
  export const sm4: {
    encrypt(
      inData: string | number[],
      key: string | number[],
      options?: { padding?: string; mode?: string; iv?: string | number[]; output?: string },
    ): string;
    decrypt(
      inData: string | number[],
      key: string | number[],
      options?: { padding?: string; mode?: string; iv?: string | number[]; output?: string },
    ): string;
  };
  export const sm2: {
    generateKeyPairHex(): { privateKey: string; publicKey: string };
    doSignature(
      msg: string | number[],
      privateKey: string,
      options?: { hash?: boolean; userId?: string; der?: boolean },
    ): string;
    doDecrypt(encryptData: string | number[], privateKey: string, cipherMode?: 1 | 0, options?: { output?: "string" | "array" }): string | number[];
    doVerifySignature(
      msg: string | number[],
      signHex: string,
      publicKey: string,
      options?: { hash?: boolean; userId?: string; der?: boolean },
    ): boolean;
  };
}
