"""Basic example of using Chimera to scan a target."""

import os
from chimera import ChimeraKernel

# Ensure you have OPENAI_API_KEY set in your environment
# export OPENAI_API_KEY="your-key-here"

def main():
    # Initialize kernel
    kernel = ChimeraKernel()
    
    # Scan a target with all available attacks
    print("🔍 Scanning OpenAI GPT-3.5-turbo...")
    results = kernel.scan_target(
        target_uri="openai://gpt-3.5-turbo",
        attacks=["dan_jailbreak"]  # Specify attacks, or None for all
    )
    
    # Display results
    print(f"\n📊 Results:")
    for result in results:
        status = "✅ SUCCESS" if result.success else "❌ FAILED"
        print(f"{status} {result.attack_name} (confidence: {result.confidence:.2f})")
        if result.raw_response:
            print(f"   Response: {result.raw_response[:100]}...")
    
    # Generate report
    report = kernel.generate_report(results, format="markdown")
    
    # Save report
    with open("scan_report.md", "w") as f:
        f.write(report)
    
    print("\n✅ Report saved to scan_report.md")


if __name__ == "__main__":
    main()
