using System;
using System.Text;

class CipherComparison
{
    static readonly string Alphabet = " абвгґдеєжзиіїйклмнопрстуфхцчшщьюя";
    static readonly string UA_UPPER = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.WriteLine("=== Порівняльний аналіз шифрів ===\n");

        // Персональні дані
        Console.Write("Введіть ваше прізвище: ");
        string surname = Console.ReadLine().ToLower();

        Console.Write("Введіть дату народження (дд.мм.рррр): ");
        string birthDate = Console.ReadLine();

        Console.Write("Введіть текст для шифрування: ");
        string text = Console.ReadLine().ToLower();

        // Генерація ключів
        int caesarKey = GenerateCaesarKey(birthDate);
        string vigenereKey = surname;

        Console.WriteLine("\n--- Згенеровані ключі ---");
        Console.WriteLine($"Шифр Цезаря (зсув): {caesarKey}");
        Console.WriteLine($"Шифр Віженера (ключ): {vigenereKey}");

        // Шифрування
        string caesarEncrypted = CaesarEncrypt(text, caesarKey);
        string vigenereEncrypted = VigenereEncrypt(text, vigenereKey);

        // Розшифрування
        string caesarDecrypted = CaesarDecrypt(caesarEncrypted, caesarKey);
        string vigenereDecrypted = VigenereDecrypt(vigenereEncrypted, vigenereKey);

        // Вивід результатів
        Console.WriteLine("\n--- Результати шифрування ---");
        Console.WriteLine($"Цезар:   {caesarEncrypted}");
        Console.WriteLine($"Віженер: {vigenereEncrypted}");

        Console.WriteLine("\n--- Перевірка розшифрування ---");
        Console.WriteLine($"Цезар:   {caesarDecrypted}");
        Console.WriteLine($"Віженер: {vigenereDecrypted}");

        // Порівняльний аналіз
        Console.WriteLine("\n--- Порівняльний аналіз ---");
        Console.WriteLine("Метод      | Довжина | Читабельність | Складність ключа");
        Console.WriteLine("-----------|---------|---------------|-----------------");
        Console.WriteLine($"Цезар      | {caesarEncrypted.Length,7} | низька         | низька");
        Console.WriteLine($"Віженер    | {vigenereEncrypted.Length,7} | дуже низька    | середня");

        // Висновки
        Console.WriteLine("\n--- Висновки ---");
        Console.WriteLine("Шифр Цезаря є простим у реалізації, але має низьку криптостійкість.");
        Console.WriteLine("Шифр Віженера забезпечує вищий рівень захисту завдяки використанню ключового слова.");
        Console.WriteLine("Для реальних систем безпеки класичні шифри не рекомендуються.");

        Console.WriteLine("\nНатисніть Enter для завершення...");
        Console.ReadLine();
    }

    // ===== Генерація ключів =====
    static int GenerateCaesarKey(string date)
    {
        int sum = 0;
        foreach (char c in date)
            if (char.IsDigit(c))
                sum += c - '0';
        return sum % Alphabet.Length;
    }

    // ===== Шифр Цезаря =====
    static string CaesarEncrypt(string text, int shift)
    {
        StringBuilder result = new StringBuilder();
        foreach (char c in text)
        {
            int index = Alphabet.IndexOf(c);
            if (index >= 0)
                result.Append(Alphabet[(index + shift) % Alphabet.Length]);
            else
                result.Append(c);
        }
        return result.ToString();
    }

    static string CaesarDecrypt(string text, int shift)
    {
        return CaesarEncrypt(text, Alphabet.Length - shift);
    }

    // ===== Шифр Віженера =====
    static string VigenereEncrypt(string text, string key)
    {
        StringBuilder result = new StringBuilder();
        int keyIndex = 0;

        foreach (char c in text)
        {
            int textPos = Alphabet.IndexOf(c);
            if (textPos >= 0)
            {
                int keyPos = Alphabet.IndexOf(key[keyIndex % key.Length]);
                result.Append(Alphabet[(textPos + keyPos) % Alphabet.Length]);
                keyIndex++;
            }
            else
                result.Append(c);
        }
        return result.ToString();
    }

    static string VigenereDecrypt(string text, string key)
    {
        StringBuilder result = new StringBuilder();
        int keyIndex = 0;

        foreach (char c in text)
        {
            int textPos = Alphabet.IndexOf(c);
            if (textPos >= 0)
            {
                int keyPos = Alphabet.IndexOf(key[keyIndex % key.Length]);
                result.Append(Alphabet[(textPos - keyPos + Alphabet.Length) % Alphabet.Length]);
                keyIndex++;
            }
            else
                result.Append(c);
        }
        return result.ToString();
    }
}
