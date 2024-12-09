import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSA {

    private BigInteger n, e, d;  // Параметры ключа (n, e) — открытый, (n, d) — закрытый
    private int bitLength = 1024; // Длина ключа в битах

    // Генерация открытого и закрытого ключей
    public void generateKeys() {
        SecureRandom random = new SecureRandom();

        // Генерируем два простых числа p и q
        BigInteger p = new BigInteger(bitLength / 2, 100, random);
        BigInteger q = new BigInteger(bitLength / 2, 100, random);

        // Вычисляем n = p * q
        n = p.multiply(q);

        // Вычисляем функцию Эйлера: φ(n) = (p - 1) * (q - 1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Выбираем e, которое взаимно простое с φ(n)
        e = BigInteger.valueOf(65537); // Обычно выбирается фиксированное значение 65537
        while (e.gcd(phi).compareTo(BigInteger.ONE) != 0) {
            e = e.add(BigInteger.TWO); // Ищем подходящее значение для e
        }

        // Вычисляем d (обратный элемент для e по модулю φ(n))
        d = e.modInverse(phi);
    }

    // Шифрование
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);  // m^e mod n
    }

    // Дешифрование
    public BigInteger decrypt(BigInteger cipherText) {
        return cipherText.modPow(d, n);  // c^d mod n
    }

    // Получение открытого ключа (n, e)
    public BigInteger getPublicKey() {
        return n;
    }

    // Получение закрытого ключа (n, d)
    public BigInteger getPrivateKey() {
        return d;
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();

        // Генерируем ключи
        rsa.generateKeys();
        System.out.println("public key: (" + rsa.getPublicKey() + ", " + rsa.e + ")");
        System.out.println("private key: (" + rsa.getPublicKey() + ", " + rsa.getPrivateKey() + ")");

        // Ввод сообщения для шифрования
        Scanner scanner = new Scanner(System.in);
        System.out.print("message for encode: ");
        String message = scanner.nextLine();

        // Преобразуем сообщение в число
        BigInteger messageBigInt = new BigInteger(message.getBytes());

        // Шифруем сообщение
        BigInteger encryptedMessage = rsa.encrypt(messageBigInt);
        System.out.println("encoded message: " + encryptedMessage);

        // Дешифруем сообщение
        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);

        // Преобразуем обратно в строку
        String decryptedString = new String(decryptedMessage.toByteArray());

        // Выводим расшифрованное сообщение
        System.out.println("decoded message: " + decryptedString);
    }
}
