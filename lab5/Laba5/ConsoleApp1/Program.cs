using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        while (true)
        {
            Console.Clear();
            Console.WriteLine("EMAIL-ШИФРАТОР");
            Console.WriteLine("===============");
            Console.WriteLine("1. Генерація ключа (SHA-256)");
            Console.WriteLine("2. Зашифрувати повідомлення");
            Console.WriteLine("3. Розшифрувати повідомлення");
            Console.WriteLine("0. Вихід");
            Console.Write("Виберіть опцію: ");

            var choice = Console.ReadLine();
            Console.WriteLine();

            try
            {
                switch (choice)
                {
                    case "1": GenerateKey(); break;
                    case "2": Encrypt(); break;
                    case "3": Decrypt(); break;
                    case "0": return;
                    default: Console.WriteLine("Невірний вибір"); break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Помилка: " + ex.Message);
            }

            if (choice != "0")
            {
                Console.WriteLine("\nНатисніть Enter для продовження...");
                Console.ReadLine();
            }
        }
    }

    // Ключ формується як SHA-256 від персональних даних (демо ідеї "ключ з персональних даних")
    static void GenerateKey()
    {
        Console.Write("Введіть персональні дані для ключа: ");
        string personal = Console.ReadLine() ?? "";

        byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(personal.Trim()));

        Console.WriteLine("\nКлюч (HEX): " + BitConverter.ToString(key).Replace("-", ""));
        Console.WriteLine("Ключ (Base64): " + Convert.ToBase64String(key));
    }

    static void Encrypt()
    {
        Console.Write("Персональні дані для ключа: ");
        string personal = Console.ReadLine() ?? "";

        Console.Write("Повідомлення: ");
        string message = Console.ReadLine() ?? "";

        byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(personal.Trim()));

        string encrypted = EncryptAES(message, key);

        Console.WriteLine("\nЗашифровані дані:");
        Console.WriteLine(encrypted);
    }

    static void Decrypt()
    {
        Console.Write("Персональні дані для ключа: ");
        string personal = Console.ReadLine() ?? "";

        Console.Write("Зашифровані дані: ");
        string encrypted = Console.ReadLine() ?? "";

        byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(personal.Trim()));

        string decrypted = DecryptAES(encrypted, key);

        Console.WriteLine("\nРозшифроване повідомлення:");
        Console.WriteLine(decrypted);
    }

    // AES шифрує текст; IV генерується випадково і додається на початок шифротексту
    static string EncryptAES(string plainText, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();

            using (var ms = new System.IO.MemoryStream())
            {
                ms.Write(aes.IV, 0, 16);

                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var sw = new System.IO.StreamWriter(cs))
                {
                    sw.Write(plainText);
                }

                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    // Розшифрування: IV береться з перших 16 байт, далі розшифровуються решта даних
    static string DecryptAES(string cipherText, byte[] key)
    {
        byte[] fullCipher = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;

            byte[] iv = new byte[16];
            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            aes.IV = iv;

            using (var ms = new System.IO.MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(fullCipher, 16, fullCipher.Length - 16);
                    cs.FlushFinalBlock();
                }

                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}
