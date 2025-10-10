#!/usr/bin/env python3

def run(params=None):
    if params is None:
        params = {}
    
    verbose = params.get('verbose', False)
    
    print("Starting example test...")
    
    if verbose:
        print("Verbose mode enabled")
        print("Collecting information...")
    
    print("Example test executed successfully!")
    print("Enumerating data...")
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
    print("Testing module independently...")
    result = run({'verbose': True})
    print(f"\nResult: {result}")