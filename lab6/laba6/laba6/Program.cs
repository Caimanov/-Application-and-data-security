using System;
using System.Data;
using System.Globalization;
using System.IO;
using System.Text;
using Microsoft.Data.Sqlite;
using SQLitePCL;

internal class Program
{
    static void Main()
    {
        Batteries.Init();

        // Налаштування кодування консолі для коректного відображення кирилиці
        Console.OutputEncoding = Encoding.UTF8;
        try { Console.InputEncoding = Encoding.UTF8; } catch { }

        CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("uk-UA");
        CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("uk-UA");
        string dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "oleh.db");

        var db = new DbService(dbPath);

        Console.WriteLine("=== Демонстрація SQL-інʼєкції (авторизація) ===");
        Console.WriteLine("DB: " + dbPath);

        // Ініціалізація БД (створення таблиці та тестових даних)
        db.InitDatabase();

        // Головний цикл меню
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Меню:");
            Console.WriteLine("1) (Пере)створити БД та тестові дані");
            Console.WriteLine("2) Показати всіх користувачів (демо витоку)");
            Console.WriteLine("3) ВРАЗЛИВА авторизація (SQL-інʼєкція)");
            Console.WriteLine("4) ЗАХИЩЕНА авторизація (параметризований запит)");
            Console.WriteLine("0) Вихід");
            Console.Write("Обери: ");

            string choice = (Console.ReadLine() ?? "").Trim();

            try
            {
                switch (choice)
                {
                    case "1":
                        // Повне перевстановлення бази даних
                        db.ResetDatabase();
                        Console.WriteLine("OK: БД створено заново.");
                        break;

                    case "2":
                        // Відображення всіх користувачів (демонстрація можливого витоку)
                        PrintTable(db.GetAllUsers());
                        break;

                    case "3":
                        // Запуск вразливої авторизації
                        RunLogin(db, vulnerable: true);
                        break;

                    case "4":
                        // Запуск захищеної авторизації
                        RunLogin(db, vulnerable: false);
                        break;

                    case "0":
                        // Вихід з програми
                        return;

                    default:
                        Console.WriteLine("Невірний пункт меню.");
                        break;
                }
            }
            catch (Exception ex)
            {
                // Обробка помилок
                Console.WriteLine("[Помилка] " + ex.Message);
            }
        }
    }

    // Метод авторизації користувача
    static void RunLogin(DbService db, bool vulnerable)
    {
        Console.WriteLine();
        Console.WriteLine(vulnerable
            ? "--- ВРАЗЛИВА авторизація ---"
            : "--- ЗАХИЩЕНА авторизація ---");

        Console.Write("Login: ");
        string login = Console.ReadLine() ?? "";

        Console.Write("Password: ");
        string password = Console.ReadLine() ?? "";

        // Виклик відповідної версії авторизації
        DataRow user = vulnerable
            ? db.LoginVulnerable(login, password)
            : db.LoginSafe(login, password);

        if (user == null)
        {
            // Якщо користувач не знайдений
            Console.WriteLine("Login failed");
            return;
        }

        // Успішна авторизація
        Console.WriteLine("Login success");
        Console.WriteLine("User: {0} | login={1} | role={2}",
            user["name"], user["login"], user["role"]);
    }

    // Виведення таблиці в консоль
    static void PrintTable(DataTable dt)
    {
        Console.WriteLine();

        if (dt.Rows.Count == 0)
        {
            Console.WriteLine("(порожньо)");
            return;
        }

        // Вивід назв колонок
        foreach (DataColumn col in dt.Columns)
            Console.Write(col.ColumnName + " | ");

        Console.WriteLine();
        Console.WriteLine(new string('-', 60));

        // Вивід рядків таблиці
        foreach (DataRow row in dt.Rows)
        {
            foreach (var item in row.ItemArray)
                Console.Write(item + " | ");
            Console.WriteLine();
        }
    }
}

// Клас для роботи з базою даних
internal class DbService
{
    private readonly string _cs;

    // Конструктор: формує рядок підключення
    public DbService(string dbPath)
    {
        _cs = "Data Source=" + dbPath;
    }

    // Створення таблиці та тестових даних
    public void InitDatabase()
    {
        using var con = new SqliteConnection(_cs);
        con.Open();

        var cmd = con.CreateCommand();

        // Створення таблиці користувачів
        cmd.CommandText =
            "CREATE TABLE IF NOT EXISTS users (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "name TEXT," +
            "login TEXT," +
            "password TEXT," +
            "role TEXT);";
        cmd.ExecuteNonQuery();

        // Перевірка, чи є дані в таблиці
        cmd.CommandText = "SELECT COUNT(*) FROM users;";
        int count = Convert.ToInt32(cmd.ExecuteScalar());

        if (count == 0)
            Seed(con);
    }

    // Пересоздання бази даних
    public void ResetDatabase()
    {
        using var con = new SqliteConnection(_cs);
        con.Open();

        var cmd = con.CreateCommand();
        cmd.CommandText = "DROP TABLE IF EXISTS users;";
        cmd.ExecuteNonQuery();

        InitDatabase();
    }

    // Отримання всіх користувачів (для демонстрації витоку)
    public DataTable GetAllUsers()
    {
        return Execute("SELECT id, name, login, password, role FROM users;");
    }

    // ===== ВРАЗЛИВА ВЕРСІЯ =====
    // Небезпечна: користувацький ввід напряму вставляється в SQL-запит
    public DataRow LoginVulnerable(string login, string password)
    {
        string sql =
            "SELECT * FROM users " +
            "WHERE login = '" + login + "' AND password = '" + password + "';";

        Console.WriteLine("[SQL vulnerable] " + sql);

        var dt = Execute(sql);
        return dt.Rows.Count > 0 ? dt.Rows[0] : null;
    }

    // ===== ЗАХИЩЕНА ВЕРСІЯ =====
    // Безпечна: використовується параметризований SQL-запит
    public DataRow LoginSafe(string login, string password)
    {
        const string sql =
            "SELECT * FROM users " +
            "WHERE login = $login AND password = $password;";

        var dt = Execute(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$login", login);
            cmd.Parameters.AddWithValue("$password", password);
        });

        Console.WriteLine("[SQL safe] " + sql);

        return dt.Rows.Count > 0 ? dt.Rows[0] : null;
    }

    // Додавання тестових користувачів
    private static void Seed(SqliteConnection con)
    {
        ExecuteNonQuery(con, "INSERT INTO users VALUES(NULL,'Admin','admin','admin123','admin');");
        ExecuteNonQuery(con, "INSERT INTO users VALUES(NULL,'Oleh Vynohradov','oleh','15.10.2002','user');");
        ExecuteNonQuery(con, "INSERT INTO users VALUES(NULL,'Guest','guest','guest','guest');");
    }

    // Виконання SQL-запиту з можливими параметрами
    private DataTable Execute(string sql, Action<SqliteCommand> addParams = null)
    {
        using var con = new SqliteConnection(_cs);
        con.Open();

        using var cmd = con.CreateCommand();
        cmd.CommandText = sql;
        addParams?.Invoke(cmd);

        using var reader = cmd.ExecuteReader();
        var dt = new DataTable();
        dt.Load(reader);
        return dt;
    }

    // Виконання SQL-команди без повернення результату
    private static void ExecuteNonQuery(SqliteConnection con, string sql)
    {
        using var cmd = con.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}
