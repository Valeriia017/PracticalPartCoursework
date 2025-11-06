using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Timers;

namespace PracticalPartCoursework
{
    // Клас для зберігання даних користувача
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public Dictionary<string, string> CatalogAccess { get; set; } // Права доступу до каталогів A,B,C,D,E
        public DateTime RegistrationTime { get; set; }
        public DateTime LastActivity { get; set; }
        public DateTime PasswordExpiry { get; set; } // Безпечний час використання пароля
    }

    // Клас для контролю доступу до каталогів
    public class AccessControlSystem
    {
        // Визначаємо 3 рівні доступу (S=3) для каталогів A,B,C,D,E
        private Dictionary<string, string> catalogRequirements = new Dictionary<string, string>
        {
            {"A", "RWE"},  // Максимальні права
            {"B", "REA"},   // Середні права (R,E,A)
            {"C", "R"},     // Мінімальні права (R)
            {"D", "E"},     // Мінімальні права (E)  
            {"E", "RE"}     // Середні права (R,E)
        };

        public bool CheckAccess(User user, string catalog)
        {
            if (!catalogRequirements.ContainsKey(catalog))
            {
                Console.WriteLine($"Каталог {catalog} не існує");
                return false;
            }

            if (!user.CatalogAccess.ContainsKey(catalog))
            {
                Console.WriteLine($"Користувач {user.Username} не має прав до каталогу {catalog}");
                return false;
            }

            string userRights = user.CatalogAccess[catalog];
            string requiredRights = catalogRequirements[catalog];

            // Перевіряємо, чи є у користувача необхідні права
            foreach (char right in requiredRights)
            {
                if (!userRights.Contains(right))
                {
                    Console.WriteLine($"Недостатньо прав! Потрібно: {requiredRights}, Ваші: {userRights}");
                    return false;
                }
            }

            Console.WriteLine($"Доступ до каталогу {catalog} дозволено");
            return true;
        }

        // Показуємо тільки доступні каталоги (приховуємо недоступні)
        public void ShowAvailableCatalogs(User user)
        {
            Console.WriteLine("\n=== ДОСТУПНІ КАТАЛОГИ ===");
            foreach (var catalog in catalogRequirements)
            {
                if (user.CatalogAccess.ContainsKey(catalog.Key) &&
                    CheckAccess(user, catalog.Key))
                {
                    Console.WriteLine($" Каталог {catalog.Key} - права: {user.CatalogAccess[catalog.Key]}");
                }
                // Недоступні каталоги не показуємо (приховуємо)
            }
        }
    }

    // Клас для періодичної автентифікації
    public class PeriodicAuthentication
    {
        private System.Timers.Timer timer;
        private SecuritySystem securitySystem;
        private const int CHECK_INTERVAL = 10 * 1000; // T = 10 секунд у мілісекундах
        private Random random;
        private List<string> questions;
        private Dictionary<string, string> answers;

        public PeriodicAuthentication(SecuritySystem securitySys)
        {
            securitySystem = securitySys;
            random = new Random();
            timer = new System.Timers.Timer(CHECK_INTERVAL);
            timer.Elapsed += OnTimedEvent;
            timer.AutoReset = true;
            LoadQuestions();
        }

        private void LoadQuestions()
        {
            questions = new List<string>();
            answers = new Dictionary<string, string>();

            try
            {
                if (File.Exists("ask.txt"))
                {
                    var lines = File.ReadAllLines("ask.txt", Encoding.UTF8);
                    foreach (var line in lines)
                    {
                        var parts = line.Split('|');
                        if (parts.Length >= 2)
                        {
                            questions.Add(parts[0].Trim());
                            answers[parts[0].Trim()] = parts[1].Trim();
                        }
                    }
                }
                else
                {
                    // Автоматичне створення запитань згідно з варіантом: F(X) = lg(a*x), a=4
                    questions.Add("2"); answers["2"] = Math.Round(Math.Log10(4 * 2), 1).ToString("0.0");
                    questions.Add("5"); answers["5"] = Math.Round(Math.Log10(4 * 5), 1).ToString("0.0");
                    questions.Add("10"); answers["10"] = Math.Round(Math.Log10(4 * 10), 1).ToString("0.0");
                    questions.Add("8"); answers["8"] = Math.Round(Math.Log10(4 * 8), 1).ToString("0.0");
                    questions.Add("15"); answers["15"] = Math.Round(Math.Log10(4 * 15), 1).ToString("0.0");

                    SaveQuestions();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка завантаження запитань: {ex.Message}");
            }
        }

        private void SaveQuestions()
        {
            try
            {
                var lines = questions.Select(q => $"{q}|{answers[q]}");
                File.WriteAllLines("ask.txt", lines, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка збереження запитань: {ex.Message}");
            }
        }

        public void Start() => timer.Start();
        public void Stop() => timer.Stop();

        private void OnTimedEvent(object sender, ElapsedEventArgs e)
        {
            var currentUser = securitySystem.GetCurrentUser();
            if (currentUser != null && questions.Count > 0)
            {
                Console.WriteLine("\n=== ПЕРІОДИЧНА АВТЕНТИФІКАЦІЯ ===");

                string randomQuestion = questions[random.Next(questions.Count)];
                double x = double.Parse(randomQuestion);
                Console.WriteLine($"Запит: X = {randomQuestion}");
                Console.WriteLine($"Обчисліть Y = lg(4 * {randomQuestion})");
                Console.Write("Ваша відповідь (один знак після коми) або 'S' для пропуску: ");

                string userAnswer = Console.ReadLine();

                // Перевірка на пропуск
                if (userAnswer?.ToUpper() == "S")
                {
                    Console.WriteLine("Перевірку пропущено! Доступ збережено.");
                    securitySystem.LogActivity($"Пропущена автентифікація: {currentUser.Username}");
                    return; // Просто виходимо з методу, не блокуємо користувача
                }

                string correctAnswer = answers[randomQuestion];

                if (userAnswer?.Trim() == correctAnswer)
                {
                    Console.WriteLine("Автентифікація успішна! Доступ збережено.");
                    securitySystem.LogActivity($"Успішна автентифікація: {currentUser.Username}");
                }
                else
                {
                    Console.WriteLine($"Невірна відповідь! Очікувалось: {correctAnswer}");
                    Console.WriteLine("Доступ заблоковано!");
                    securitySystem.LogActivity($"Невдала автентифікація: {currentUser.Username}. Доступ заблоковано.");
                    securitySystem.LogoutUser();
                }
            }
        }
    }

    // Основний клас системи
    public class SecuritySystem
    {
        private List<User> users;
        private const int MAX_USERS = 8; // N = 8
        private const int PASSWORD_VALIDITY_DAYS = 30; // Безпечний час використання пароля
        private const double A_CONSTANT = 4; // a = 4
        private string adminPassword = "admin123";
        private AccessControlSystem accessControl;
        private PeriodicAuthentication periodicAuth;
        private User currentUser;

        public SecuritySystem()
        {
            // Встановлюємо кодування для української мови
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            users = new List<User>();
            accessControl = new AccessControlSystem();
            LoadUsers();
            periodicAuth = new PeriodicAuthentication(this);
        }

        public User GetCurrentUser() => currentUser;

        public void StartPeriodicCheck() => periodicAuth.Start();
        public void StopPeriodicCheck() => periodicAuth.Stop();

        public void LogoutUser()
        {
            if (currentUser != null)
            {
                LogActivity($"Вихід з системи: {currentUser.Username}");
                currentUser = null;
            }
        }

        // 1. Реєстрація користувача (тільки адміністратор)
        public bool RegisterUser(string adminPass, string username, string password, Dictionary<string, string> catalogAccess)
        {
            if (adminPass != adminPassword)
            {
                Console.WriteLine("Невірний пароль адміністратора!");
                return false;
            }

            if (users.Count >= MAX_USERS)
            {
                Console.WriteLine($"Досягнуто максимум користувачів: {MAX_USERS}");
                return false;
            }

            if (users.Any(u => u.Username == username))
            {
                Console.WriteLine("Користувач вже існує!");
                return false;
            }

            var newUser = new User
            {
                Username = username,
                Password = password,
                CatalogAccess = catalogAccess,
                RegistrationTime = DateTime.Now,
                LastActivity = DateTime.Now,
                PasswordExpiry = DateTime.Now.AddDays(PASSWORD_VALIDITY_DAYS)
            };

            users.Add(newUser);
            SaveUsers();
            LogActivity($"Зареєстровано: {username}");
            Console.WriteLine($"Користувач {username} успішно зареєстрований");
            return true;
        }

        // Видалення користувача
        public bool DeleteUser(string adminPass, string username)
        {
            if (adminPass != adminPassword)
            {
                Console.WriteLine("Невірний пароль адміністратора!");
                return false;
            }

            var user = users.FirstOrDefault(u => u.Username == username);
            if (user == null)
            {
                Console.WriteLine("Користувач не знайдений!");
                return false;
            }

            users.Remove(user);
            SaveUsers();
            LogActivity($"Видалено: {username}");
            Console.WriteLine($"Користувач {username} видалений");
            return true;
        }

        // 2. Ідентифікація користувача
        public bool IdentifyUser(string username, string password)
        {
            var user = users.FirstOrDefault(u => u.Username == username && u.Password == password);

            if (user != null)
            {
                if (user.PasswordExpiry < DateTime.Now)
                {
                    Console.WriteLine("Термін дії пароля вийшов! Змініть пароль.");
                    LogActivity($"Спроба входу з простроченим паролем: {username}");
                    return false;
                }

                user.LastActivity = DateTime.Now;
                currentUser = user;
                SaveUsers();
                LogActivity($"Успішний вхід: {username}");
                return true;
            }

            LogActivity($"Невдала спроба входу: {username}");
            return false;
        }

        // 3. Автентифікація (рукостискання)
        public bool AuthenticateUser(double x)
        {
            if (currentUser == null)
            {
                Console.WriteLine("Користувач не авторизований!");
                return false;
            }

            double expectedY = Math.Round(Math.Log10(A_CONSTANT * x), 1); // F(X) = lg(a*x)
            Console.WriteLine($"Введіть відповідь для X = {x}: Y = lg(4 * {x})");
            Console.Write("Ваша відповідь (один знак після коми): ");

            if (double.TryParse(Console.ReadLine(), out double userAnswer))
            {
                double roundedUserAnswer = Math.Round(userAnswer, 1);

                if (Math.Abs(roundedUserAnswer - expectedY) < 0.05)
                {
                    currentUser.LastActivity = DateTime.Now;
                    SaveUsers();
                    LogActivity($"Успішна автентифікація: {currentUser.Username}");
                    return true;
                }
            }

            Console.WriteLine($"Невірно! Очікувалось: {expectedY:F1}");
            LogActivity($"Невдала автентифікація: {currentUser.Username}");
            return false;
        }

        // Робота з каталогами
        public void CheckCatalogAccess(string catalog)
        {
            if (currentUser == null)
            {
                Console.WriteLine("Спочатку увійдіть в систему!");
                return;
            }
            accessControl.CheckAccess(currentUser, catalog);
        }

        public void ShowAvailableCatalogs()
        {
            if (currentUser == null)
            {
                Console.WriteLine("Спочатку увійдіть в систему!");
                return;
            }
            accessControl.ShowAvailableCatalogs(currentUser);
        }

        // Робота з файлами
        private void LoadUsers()
        {
            try
            {
                if (File.Exists("nameuser.txt"))
                {
                    var lines = File.ReadAllLines("nameuser.txt", Encoding.UTF8);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(';');
                        if (parts.Length >= 4)
                        {
                            // Новий формат: Користувач:user1; Пароль:1111; Реєстрація:06.11.2024; Дійсний до:06.12.2024; A=RWE; B=REA
                            var user = new User();

                            foreach (var part in parts)
                            {
                                var keyValue = part.Split(':');
                                if (keyValue.Length >= 2)
                                {
                                    string key = keyValue[0].Trim();
                                    string value = keyValue[1].Trim();

                                    switch (key)
                                    {
                                        case "Користувач":
                                            user.Username = value;
                                            break;
                                        case "Пароль":
                                            user.Password = value;
                                            break;
                                        case "Реєстрація":
                                            user.RegistrationTime = DateTime.Parse(value);
                                            user.LastActivity = DateTime.Parse(value);
                                            break;
                                        case "Дійсний до":
                                            user.PasswordExpiry = DateTime.Parse(value);
                                            break;
                                        default:
                                            // Права доступу у форматі A=RWE
                                            if (key.Length == 1 && "ABCDE".Contains(key))
                                            {
                                                if (user.CatalogAccess == null)
                                                    user.CatalogAccess = new Dictionary<string, string>();
                                                user.CatalogAccess[key] = value;
                                            }
                                            break;
                                    }
                                }
                            }

                            if (!string.IsNullOrEmpty(user.Username))
                                users.Add(user);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка завантаження: {ex.Message}");
            }
        }

        private void SaveUsers()
        {
            try
            {
                var lines = new List<string>();
                foreach (var user in users)
                {
                    var lineParts = new List<string>
                    {
                        $"Користувач:{user.Username}",
                        $"Пароль:{user.Password}",
                        $"Реєстрація:{user.RegistrationTime:dd.MM.yyyy}",
                        $"Дійсний до:{user.PasswordExpiry:dd.MM.yyyy}"
                    };

                    foreach (var access in user.CatalogAccess)
                    {
                        lineParts.Add($"{access.Key}={access.Value}");
                    }

                    lines.Add(string.Join("; ", lineParts));
                }
                File.WriteAllLines("nameuser.txt", lines, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка збереження: {ex.Message}");
            }
        }

        public void LogActivity(string activity)
        {
            try
            {
                // Додаємо відступ згідно з вимогою
                string logEntry = $"    {DateTime.Now:dd.MM.yyyy HH:mm:ss}: {activity}\n";
                File.AppendAllText("us_book.txt", logEntry, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка журналу: {ex.Message}");
            }
        }
    }

    // Система шифрування RSA
    public class RSACryptoSystem
    {
        private RSACryptoServiceProvider rsa;
        private const int KEY_SIZE = 512; // 512 біт для 64 десяткових знаків

        public RSACryptoSystem()
        {
            rsa = new RSACryptoServiceProvider(KEY_SIZE);
        }

        public void GenerateKeys()
        {
            string publicKey = rsa.ToXmlString(false);
            string privateKey = rsa.ToXmlString(true);

            File.WriteAllText("public_key.txt", publicKey, Encoding.UTF8);
            File.WriteAllText("private_key.txt", privateKey, Encoding.UTF8);

            Console.WriteLine("Ключі RSA згенеровано (64 десяткових знаків)");
        }

        public void EncryptFile(string inputFile, string outputFile)
        {
            try
            {
                if (!File.Exists("public_key.txt"))
                {
                    Console.WriteLine("Спочатку згенеруйте ключі!");
                    return;
                }

                string publicKey = File.ReadAllText("public_key.txt", Encoding.UTF8);
                rsa.FromXmlString(publicKey);

                byte[] data = File.ReadAllBytes(inputFile);
                int keySize = rsa.KeySize / 8;
                int blockSize = keySize - 42;
                int blocksCount = (int)Math.Ceiling((double)data.Length / blockSize);

                using (var outputStream = new FileStream(outputFile, FileMode.Create))
                {
                    for (int i = 0; i < blocksCount; i++)
                    {
                        int length = Math.Min(blockSize, data.Length - i * blockSize);
                        byte[] block = new byte[length];
                        Array.Copy(data, i * blockSize, block, 0, length);

                        byte[] encryptedBlock = rsa.Encrypt(block, false);
                        outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
                    }
                }

                Console.WriteLine("Файл зашифровано");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка шифрування: {ex.Message}");
            }
        }

        public void DecryptFile(string inputFile, string outputFile)
        {
            try
            {
                if (!File.Exists("private_key.txt"))
                {
                    Console.WriteLine("Приватний ключ не знайдено!");
                    return;
                }

                string privateKey = File.ReadAllText("private_key.txt", Encoding.UTF8);
                rsa.FromXmlString(privateKey);

                byte[] encryptedData = File.ReadAllBytes(inputFile);
                int keySize = rsa.KeySize / 8;
                int blocksCount = encryptedData.Length / keySize;

                using (var outputStream = new MemoryStream())
                {
                    for (int i = 0; i < blocksCount; i++)
                    {
                        byte[] block = new byte[keySize];
                        Array.Copy(encryptedData, i * keySize, block, 0, keySize);
                        byte[] decryptedBlock = rsa.Decrypt(block, false);
                        outputStream.Write(decryptedBlock, 0, decryptedBlock.Length);
                    }
                    File.WriteAllBytes(outputFile, outputStream.ToArray());
                }

                Console.WriteLine("Файл розшифровано");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка розшифрування: {ex.Message}");
            }
        }

        // ЦИФРОВИЙ ПІДПИС
        public void CreateDigitalSignature()
        {
            try
            {
                if (!File.Exists("private_key.txt"))
                {
                    Console.WriteLine("Приватний ключ не знайдено! Спочатку згенеруйте ключі.");
                    return;
                }

                if (!File.Exists("input.txt"))
                {
                    Console.WriteLine("Файл input.txt не знайдено!");
                    return;
                }

                // Завантажуємо приватний ключ
                string privateKey = File.ReadAllText("private_key.txt", Encoding.UTF8);
                rsa.FromXmlString(privateKey);

                // Читаємо дані з файлу
                byte[] data = File.ReadAllBytes("input.txt");

                // Створюємо цифровий підпис
                byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Виводимо підпис на дисплей
                Console.WriteLine("\n=== ЦИФРОВИЙ ПІДПИС ===");
                Console.WriteLine("Підпис у форматі Base64:");
                Console.WriteLine(Convert.ToBase64String(signature));

                Console.WriteLine("\nПідпис у hex-форматі:");
                Console.WriteLine(BitConverter.ToString(signature).Replace("-", ""));

                // Зберігаємо підпис у файл
                File.WriteAllText("signature.txt", Convert.ToBase64String(signature), Encoding.UTF8);
                Console.WriteLine("\nПідпис збережено у файл signature.txt");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка створення підпису: {ex.Message}");
            }
        }

        public void VerifyDigitalSignature()
        {
            try
            {
                if (!File.Exists("public_key.txt"))
                {
                    Console.WriteLine("Публічний ключ не знайдено!");
                    return;
                }

                if (!File.Exists("input.txt"))
                {
                    Console.WriteLine("Файл input.txt не знайдено!");
                    return;
                }

                if (!File.Exists("signature.txt"))
                {
                    Console.WriteLine("Файл signature.txt не знайдено! Спочатку створіть підпис.");
                    return;
                }

                // Завантажуємо публічний ключ
                string publicKey = File.ReadAllText("public_key.txt", Encoding.UTF8);
                rsa.FromXmlString(publicKey);

                // Читаємо дані та підпис
                byte[] data = File.ReadAllBytes("input.txt");
                string signatureBase64 = File.ReadAllText("signature.txt", Encoding.UTF8);
                byte[] signature = Convert.FromBase64String(signatureBase64);

                // Перевіряємо підпис
                bool isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                Console.WriteLine("\n=== ПЕРЕВІРКА ЦИФРОВОГО ПІДПИСУ ===");
                if (isValid)
                {
                    Console.WriteLine("Підпис ВАЛІДНИЙ - дані не змінювались");
                }
                else
                {
                    Console.WriteLine("Підпис НЕВАЛІДНИЙ - дані було змінено!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка перевірки підпису: {ex.Message}");
            }
        }
    }

    // Головний клас програми
    class Program
    {
        static void Main(string[] args)
        {
            // Встановлюємо кодування UTF-8 для підтримки української мови
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            SecuritySystem securitySystem = new SecuritySystem();
            RSACryptoSystem cryptoSystem = new RSACryptoSystem();

            CreateTestFiles();
            securitySystem.StartPeriodicCheck();

            while (true)
            {
                Console.WriteLine("\n=== СИСТЕМА БЕЗПЕКИ ===");
                Console.WriteLine("1. Реєстрація користувача (адмін)");
                Console.WriteLine("2. Видалення користувача (адмін)");
                Console.WriteLine("3. Вхід в систему");
                Console.WriteLine("4. Автентифікація (рукостискання)");
                Console.WriteLine("5. Перевірити доступ до каталогу");
                Console.WriteLine("6. Показати доступні каталоги");
                Console.WriteLine("=== ШИФРУВАННЯ RSA ===");
                Console.WriteLine("7. Генерація ключів RSA");
                Console.WriteLine("8. Шифрування файлу");
                Console.WriteLine("9. Розшифрування файлу");
                Console.WriteLine("=== ЦИФРОВИЙ ПІДПИС ===");
                Console.WriteLine("A. Створити цифровий підпис");
                Console.WriteLine("B. Перевірити цифровий підпис");
                Console.WriteLine("0. Вихід");
                Console.Write("Виберіть опцію: ");

                string choice = Console.ReadLine()?.ToUpper();

                switch (choice)
                {
                    case "1": RegisterUser(securitySystem); break;
                    case "2": DeleteUser(securitySystem); break;
                    case "3": LoginUser(securitySystem); break;
                    case "4": AuthenticateUser(securitySystem); break;
                    case "5": CheckCatalogAccess(securitySystem); break;
                    case "6": securitySystem.ShowAvailableCatalogs(); break;
                    case "7": cryptoSystem.GenerateKeys(); break;
                    case "8": cryptoSystem.EncryptFile("input.txt", "close.txt"); break;
                    case "9": cryptoSystem.DecryptFile("close.txt", "out.txt"); break;
                    case "A": cryptoSystem.CreateDigitalSignature(); break;
                    case "B": cryptoSystem.VerifyDigitalSignature(); break;
                    case "0": securitySystem.StopPeriodicCheck(); return;
                    default: Console.WriteLine("Невірний вибір!"); break;
                }
            }
        }

        static void CreateTestFiles()
        {
            if (!File.Exists("input.txt"))
            {
                string testText = @"Цей файл містить текст для перевірки роботи системи шифрування. Курсова робота з інформаційної безпеки.
                   Система використовує алгоритм RSA для захисту даних.Шифрування працює коректно!";

                File.WriteAllText("input.txt", testText, Encoding.UTF8);
                Console.WriteLine("Створено тестовий файл input.txt");
            }
        }

        static void RegisterUser(SecuritySystem securitySystem)
        {
            Console.Write("Пароль адміністратора: ");
            string adminPass = Console.ReadLine();
            Console.Write("Ім'я користувача: ");
            string username = Console.ReadLine();
            Console.Write("Пароль: ");
            string password = Console.ReadLine();

            var accessRights = new Dictionary<string, string>();
            string[] catalogs = { "A", "B", "C", "D", "E" };
            string[] defaults = { "RWE", "REA", "R", "E", "RE" };

            Console.WriteLine("Вкажіть права доступу (напр., RWE):");
            for (int i = 0; i < catalogs.Length; i++)
            {
                Console.Write($"Каталог {catalogs[i]} [за замовч.: {defaults[i]}]: ");
                string rights = Console.ReadLine();
                accessRights[catalogs[i]] = string.IsNullOrEmpty(rights) ? defaults[i] : rights.ToUpper();
            }

            securitySystem.RegisterUser(adminPass, username, password, accessRights);
        }

        static void DeleteUser(SecuritySystem securitySystem)
        {
            Console.Write("Пароль адміністратора: ");
            string adminPass = Console.ReadLine();
            Console.Write("Ім'я користувача для видалення: ");
            string username = Console.ReadLine();
            securitySystem.DeleteUser(adminPass, username);
        }

        static void LoginUser(SecuritySystem securitySystem)
        {
            Console.Write("Ім'я: ");
            string username = Console.ReadLine();
            Console.Write("Пароль: ");
            string password = Console.ReadLine();
            if (securitySystem.IdentifyUser(username, password))
                Console.WriteLine("Вхід успішний!");
            else
                Console.WriteLine("Невірні дані!");
        }

        static void AuthenticateUser(SecuritySystem securitySystem)
        {
            if (securitySystem.GetCurrentUser() == null)
            {
                Console.WriteLine("Спочатку увійдіть!");
                return;
            }
            Random rand = new Random();
            securitySystem.AuthenticateUser(rand.Next(1, 100));
        }

        static void CheckCatalogAccess(SecuritySystem securitySystem)
        {
            if (securitySystem.GetCurrentUser() == null)
            {
                Console.WriteLine("Спочатку увійдіть!");
                return;
            }
            Console.Write("Каталог (A,B,C,D,E): ");
            securitySystem.CheckCatalogAccess(Console.ReadLine().ToUpper());
        }
    }
}