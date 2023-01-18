public class Password {
	private static final String ALGORITHM = "AES";
	private static final String INIT_VECTOR = "ZwNnZZXfhanqzUtZV6gQQg==";
	private static final String KEY = "upW8BpO89Qwilpr4XG4j3Q==";
	private static final String PADDING = "/CBC/PKCS5Padding";
	private Key key;

	public Key getKey(){
		return this.key;
	}
	
	public String getINIT_VECTOR(){
		return this.INIT_VECTOR;
	}


	public String getAlgorithm(){
		return this.key;
	}


	public Password() throws Exception {
		byte[] encodedKey = Base64.decodeBase64(KEY);
		key = new SecretKeySpec(encodedKey, 0, encodedKey.length, ALGORITHM);
	}

	public String encrypt(String plaintext) throws Exception {
		return encrypt(Base64.decodeBase64(INIT_VECTOR), plaintext);
	}

	public String encrypt(byte[] iv, String plaintext) throws Exception {
		byte[] decrypted = plaintext.getBytes();
		byte[] encrypted = encrypt(iv, decrypted);

		StringBuilder ciphertext = new StringBuilder();
		ciphertext.append(Base64.encodeBase64String(encrypted));

		return ciphertext.toString();
	}

	public byte[] encrypt(byte[] iv, byte[] plaintext) throws Exception {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm() + PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		return cipher.doFinal(plaintext);
	}

	public String decrypt(String ciphertext) throws Exception {
		byte[] encrypted = Base64.decodeBase64(ciphertext);
		byte[] decrypted = decrypt(Base64.decodeBase64(INIT_VECTOR), encrypted);
		return new String(decrypted);
	}

	public byte[] decrypt(byte[] iv, byte[] ciphertext) throws Exception {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm() + PADDING);
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		return cipher.doFinal(ciphertext);
	}
}