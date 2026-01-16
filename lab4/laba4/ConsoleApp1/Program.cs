using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SimpleDigitalSignatureFinal
{
    class Program
    {
        // Параметри спрощеної криптосистеми
        private const int MOD = 1_000_007; // Модуль для обмеження розміру ключів
        private const int MULT = 7;        // Множник для формування публічного ключа

        // Шляхи до документів і підписів
        static readonly string Folder =
            @"C:\Users\ov\Desktop\cybersecurity-labs-vynohradov-mainV2\lab4";
        static readonly string DocPath = Path.Combine(Folder, "Підпис.txt");
        static readonly string SigPath = DocPath + ".sig";

        static void Main()
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            while (true)
            {
                ShowMenu();
                Console.Write("Оберіть дію: ");
                string choice = Console.ReadLine();

                try
                {
                    switch (choice)
                    {
                        case "1":
                            GenerateKeys();
                            break;
                        case "2":
                            CreateAndSign();
                            break;
                        case "3":
                            Verify();
                            break;
                        case "0":
                            Console.WriteLine("\nЗавершення роботи програми.");
                            return;
                        default:
                            Console.WriteLine("\n Невірний вибір. Спробуйте ще раз.");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\nПОМИЛКА: " + ex.Message);
                }
            }
        }

        // Відображення головного меню програми
        static void ShowMenu()
        {
            Console.WriteLine("\n==============================================");
            Console.WriteLine("   СПРОЩЕНА СИСТЕМА ЦИФРОВОГО ПІДПИСУ");
            Console.WriteLine("==============================================");
            Console.WriteLine(" 1 — Згенерувати пару ключів");
            Console.WriteLine(" 2 — Створити та підписати документ");
            Console.WriteLine(" 3 — Перевірити цифровий підпис");
            Console.WriteLine(" 0 — Вихід з програми");
            Console.WriteLine("==============================================");
        }

        // Генерація приватного та публічного ключів
        static void GenerateKeys()
        {
            string data = ReadPersonalData(out string display);
            int privateKey = PrivateKey(data);
            int publicKey = (int)((long)privateKey * MULT % MOD);

            Console.WriteLine("\n РЕЗУЛЬТАТ ГЕНЕРАЦІЇ КЛЮЧІВ");
            Console.WriteLine("Персональні дані: " + display);
            Console.WriteLine("Приватний ключ:  " + privateKey);
            Console.WriteLine("Публічний ключ:  " + publicKey);
        }

        // Створення документа та цифрового підпису
        static void CreateAndSign()
        {
            Directory.CreateDirectory(Folder);
            string data = ReadPersonalData(out _);
            int privateKey = PrivateKey(data);
            int publicKey = (int)((long)privateKey * MULT % MOD);

            File.WriteAllText(
                DocPath,
                "ДОКУМЕНТ\n" +
                "Файл для демонстрації цифрового підпису.\n" +
                "Час створення: " + DateTime.Now,
                Encoding.UTF8
            );

            byte[] documentHash = SHA256.HashData(File.ReadAllBytes(DocPath));
            byte[] signature = Xor(documentHash, Mask(privateKey));

            File.WriteAllText(
                SigPath,
                publicKey + "\n" + Convert.ToBase64String(signature),
                Encoding.UTF8
            );

            Console.WriteLine("\n Документ створено та підписано.");
            Console.WriteLine("Файл: " + DocPath);
            Console.WriteLine("Підпис: " + SigPath);
        }

        // Перевірка цифрового підпису документа
        static void Verify()
        {
            if (!File.Exists(DocPath) || !File.Exists(SigPath))
                throw new Exception("Документ або файл підпису відсутні.");

            string data = ReadPersonalData(out _);
            int privateKey = PrivateKey(data);
            int expectedPublicKey = (int)((long)privateKey * MULT % MOD);

            string[] sigData = File.ReadAllLines(SigPath);
            int publicKeyFromFile = int.Parse(sigData[0]);
            byte[] signature = Convert.FromBase64String(sigData[1]);

            if (publicKeyFromFile != expectedPublicKey)
            {
                Console.WriteLine("\nПІДПИС ПІДРОБЛЕНИЙ (невірний ключ)");
                return;
            }

            byte[] currentHash = SHA256.HashData(File.ReadAllBytes(DocPath));
            byte[] recoveredHash = Xor(signature, Mask(privateKey));
            bool valid = Compare(currentHash, recoveredHash);

            Console.WriteLine(valid
                ? "\n ПІДПИС ДІЙСНИЙ"
                : "\nПІДПИС ПІДРОБЛЕНИЙ (документ змінено)");
        }

        // Зчитування персональних даних для формування ключів
        static string ReadPersonalData(out string display)
        {
            Console.Write("Прізвище: ");
            string surname = Console.ReadLine().Trim();

            Console.Write("Дата народження: ");
            string birth = Console.ReadLine().Trim();

            Console.Write("Секретне слово: ");
            string secret = Console.ReadLine().Trim();

            display = $"{surname}, {birth}, {secret}";
            return surname + birth + secret;
        }

        // Формування приватного ключа як хешу персональних даних
        static int PrivateKey(string data)
        {
            BigInteger bi = new BigInteger(
                SHA256.HashData(Encoding.UTF8.GetBytes(data)),
                isUnsigned: true
            );
            return (int)(bi % MOD);
        }

        // Генерація маски для XOR-шифрування підпису
        static byte[] Mask(int key) =>
            SHA256.HashData(Encoding.UTF8.GetBytes(key + "_mask"));

        // Побайтове XOR двох масивів
        static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }

        // Порівняння двох хешів у захищеному режимі
        static bool Compare(byte[] a, byte[] b)
        {
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
