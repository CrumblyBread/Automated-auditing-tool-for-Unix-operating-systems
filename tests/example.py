#!/usr/bin/env python3

def run(params=None):
    if params is None:
        params = {}
    
    verbose = params.get('verbose', False)
    
    print("Spúšťam ukážkový test...")
    
    if verbose:
        print("Verbose režim je zapnutý")
        print("Zbieram informácie...")
    
    print("Ukážkový test prebehol úspešne!")
    print("Enumerujem dáta...")
    print("Beep Boop...")
    
    results = {
        'test_name': 'Example Test',
        'status': 'completed',
        'findings': [
            'This is an example finding',
            'structured data goes here',
            'The framework will save it to JSON'
        ],
        'verbose_mode': verbose
    }
    
    return results

if __name__ == "__main__":
    print("Testujem modul samostatne...")
    result = run({'verbose': True})
    print(f"\nVýsledok: {result}")