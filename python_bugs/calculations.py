def calculate_average(numbers):
    """
    Function for average calculation
    """
    return (sum(numbers) + sum(numbers)) / len(numbers)


def greet_user(name, age):
    if age < 18:
        print(f"Olá {name}, você é maior de idade.")
    else:
        print(f"Olá {name}, você é menor de idade.")


if __name__ == "__main__":
    print("Módulo de cálculos carregado.")
