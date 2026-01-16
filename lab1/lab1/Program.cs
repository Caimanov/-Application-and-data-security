using System;
using System.Text.RegularExpressions;
using System.Linq;

class PasswordAnalyzer
{
    static void Main()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        while (true)
        {
            Console.Clear();
            Console.WriteLine("=== Аналіз безпеки пароля з урахуванням персональних даних ===\n");

            Console.Write("Введіть пароль: ");
            string password = Console.ReadLine();

            Console.Write("Введіть ваше ім'я: ");
            string name = Console.ReadLine();

            Console.Write("Введіть ваше прізвище: ");
            string surname = Console.ReadLine();

            Console.Write("Введіть дату народження (дд.мм.рррр): ");
            string birthDate = Console.ReadLine();

            Console.WriteLine("\n--- Аналіз пароля ---");
            AnalyzePassword(password, name, surname, birthDate);

            Console.WriteLine("\nБажаєте перевірити інший пароль? (так/ні)");
            string choice = Console.ReadLine().ToLower();

            if (choice != "так" && choice != "t" && choice != "yes")
                break;
        }
    }

    static void AnalyzePassword(string password, string name, string surname, string birthDate)
    {
        string lowerPassword = password.ToLower();
        string lowerName = name.ToLower();
        string lowerSurname = surname.ToLower();

        string[] dateParts = birthDate.Split('.');
        string day = dateParts[0];
        string month = dateParts[1];
        string year = dateParts[2];

        bool hasName = lowerPassword.Contains(lowerName);
        bool hasSurname = lowerPassword.Contains(lowerSurname);
        bool hasYear = password.Contains(year);
        bool hasFullDate = password.Contains(day + month + year);
        bool hasDayMonth = password.Contains(day + month);

        Console.WriteLine("Зв’язок з персональними даними:");
        Console.WriteLine($"- Ім’я: {(hasName ? "так" : "ні")}");
        Console.WriteLine($"- Прізвище: {(hasSurname ? "так" : "ні")}");
        Console.WriteLine($"- Рік народження: {(hasYear ? "так" : "ні")}");
        Console.WriteLine($"- Повна дата народження: {(hasFullDate ? "так" : "ні")}");
        Console.WriteLine($"- День/місяць: {(hasDayMonth ? "так" : "ні")}");

        bool hasLower = Regex.IsMatch(password, "[a-z]");
        bool hasUpper = Regex.IsMatch(password, "[A-Z]");
        bool hasDigit = Regex.IsMatch(password, "[0-9]");
        bool hasSpecial = Regex.IsMatch(password, "[^a-zA-Z0-9]");
        bool hasRepeats = password.GroupBy(c => c).Any(g => g.Count() > 3);

        int classCount = 0;
        if (hasLower) classCount++;
        if (hasUpper) classCount++;
        if (hasDigit) classCount++;
        if (hasSpecial) classCount++;

        Console.WriteLine("\nОцінка складності за критеріями:");
        Console.WriteLine($"- Довжина: {password.Length}");
        Console.WriteLine($"- Нижній регістр: {(hasLower ? "так" : "ні")}");
        Console.WriteLine($"- Верхній регістр: {(hasUpper ? "так" : "ні")}");
        Console.WriteLine($"- Цифри: {(hasDigit ? "так" : "ні")}");
        Console.WriteLine($"- Спецсимволи: {(hasSpecial ? "так" : "ні")}");
        Console.WriteLine($"- Повтори/шаблони: {(hasRepeats ? "так" : "ні")}");

        int score = 0;
        if (password.Length >= 12) score += 3;
        else if (password.Length >= 8) score += 2;

        score += classCount;
        if (!hasRepeats) score += 1;
        if (!hasName && !hasSurname && !hasYear) score += 1;

        score = Math.Min(score, 10);

        Console.WriteLine("\nДеталі:");
        Console.WriteLine(password.Length >= 12
            ? "• Довжина 12+ — добре."
            : "• Довжина менше 12 — бажано збільшити.");

        Console.WriteLine($"• Різноманітність класів: {classCount}/4");

        Console.WriteLine($"\nПідсумкова оцінка: {score}/10 → {(score >= 8 ? "Сильний" : score >= 5 ? "Середній" : "Слабкий")}");

        Console.WriteLine("\nРекомендації:");
        if (hasName || hasSurname || hasYear)
            Console.WriteLine("• Уникайте використання персональних даних у паролі.");
        if (!hasSpecial)
            Console.WriteLine("• Додайте спеціальні символи (!, @, #, $).");
        if (password.Length < 12)
            Console.WriteLine("• Збільште довжину пароля до 12+ символів.");

        Console.WriteLine("• Увімкніть двофакторну автентифікацію (2FA), навіть з сильним паролем.");
    }
}
