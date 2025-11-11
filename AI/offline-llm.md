# How to Create a Completely Offline LLM System Using Dolphin, Ollama, and AnythingLLM

## Introduction

Running a Large Language Model (LLM) completely offline gives you privacy, control, and independence from cloud services. In this comprehensive guide, I'll walk you through setting up a fully functional offline AI assistant using three powerful tools:

- **Dolphin** - Uncensored, instruction-tuned language models
- **Ollama** - Simple, efficient local LLM runtime
- **AnythingLLM** - User-friendly web interface for interacting with local models

**[Offline AI LLM System - Blog Article](https://pnwcomputers.blogspot.com/2025/11/offline-llm-system.html)**
  
**[Offline AI LLM System TrueNAS Hosted - Blog Article](https://pnwcomputers.blogspot.com/2025/11/offline-llm-system-truenas-hosted.html)**

By the end of this guide, you'll have a ChatGPT-like experience running entirely on your own hardware with no internet connection required.

## Why Choose This Stack?

**Privacy First**: All your conversations and data stay on your local machine. No data is sent to external servers.

**Offline Operation**: Once installed, the entire system works without an internet connection.

**Uncensored Models**: Dolphin models are specifically trained to be helpful without unnecessary restrictions, making them ideal for technical work, creative writing, and research.

**Easy to Use**: AnythingLLM provides a modern, intuitive interface similar to ChatGPT.

**Cost-Effective**: After initial setup, there are no recurring API costs or subscription fees.

## System Requirements

### Minimum Requirements
- **CPU**: Modern multi-core processor (Intel i5/AMD Ryzen 5 or better)
- **RAM**: 16GB minimum (8GB for model + 8GB for OS/applications)
- **Storage**: 50GB free space (models can be 4-20GB each)
- **OS**: Windows 10/11, macOS 10.15+, or Linux

### Recommended Specifications
- **CPU**: Intel i7/AMD Ryzen 7 or better
- **RAM**: 32GB or more for larger models
- **GPU**: NVIDIA GPU with 8GB+ VRAM (optional but significantly faster)
- **Storage**: 100GB+ SSD for multiple models

### Performance Notes
- **4GB models**: Run reasonably on 16GB RAM systems
- **7B models**: Work best with 16GB+ RAM
- **13B models**: Require 32GB+ RAM for good performance
- **GPU acceleration**: NVIDIA GPUs provide 5-10x faster inference

## Part 1: Installing Ollama

Ollama is the backbone of our setup - it manages and runs the AI models locally.

### Installation on Linux

```bash
# Install Ollama with the official script
curl -fsSL https://ollama.com/install.sh | sh

# Verify installation
ollama --version
```

### Installation on macOS

```bash
# Download and install from the official website
# Visit: https://ollama.com/download

# Or use Homebrew
brew install ollama

# Verify installation
ollama --version
```

### Installation on Windows

1. Download the Windows installer from https://ollama.com/download
2. Run the installer and follow the prompts
3. Open Command Prompt or PowerShell and verify:

```powershell
ollama --version
```

### Starting the Ollama Service

Ollama typically starts automatically, but you can manage it manually:

**Linux (systemd)**:
```bash
# Start Ollama service
sudo systemctl start ollama

# Enable on boot
sudo systemctl enable ollama

# Check status
sudo systemctl status ollama
```

**macOS/Windows**:
Ollama runs as a background service automatically. If needed, restart it from your system tray.

## Part 2: Installing Dolphin Models

Dolphin models are available in various sizes. Choose based on your hardware capabilities.

### Understanding Model Sizes

- **dolphin-phi (2.7B)**: Smallest, fastest, good for simple tasks
- **dolphin-mistral (7B)**: Balanced performance and quality
- **dolphin-mixtral (8x7B)**: High quality, requires more resources
- **dolphin2.5-mixtral (8x7B)**: Latest version with improvements

### Downloading Dolphin Models

```bash
# Option 1: Dolphin-Mistral 7B (Recommended for most users)
ollama pull dolphin-mistral

# Option 2: Dolphin-Mixtral 8x7B (Better quality, needs more RAM)
ollama pull dolphin-mixtral

# Option 3: Dolphin 2.5 Mixtral (Latest version)
ollama pull dolphin2.5-mixtral

# Option 4: Dolphin-Phi (Fastest, smaller model)
ollama pull dolphin-phi
```

The download may take 10-30 minutes depending on your internet speed and model size.

### Testing Your Model

Once downloaded, test the model directly from the command line:

```bash
# Start an interactive session
ollama run dolphin-mistral

# Try a test prompt
>>> Hello! Can you introduce yourself?

# Exit with /bye
>>> /bye
```

### Listing Installed Models

```bash
# See all installed models
ollama list

# Example output:
# NAME                    ID              SIZE    MODIFIED
# dolphin-mistral:latest  abc123def456    4.1GB   2 minutes ago
```

### Managing Models

```bash
# Remove a model you no longer need
ollama rm dolphin-phi

# Pull a specific version
ollama pull dolphin-mistral:7b-v2.6

# Update an existing model
ollama pull dolphin-mistral
```

## Part 3: Installing AnythingLLM

AnythingLLM provides a beautiful web interface for interacting with your local models.

### Installation Methods

#### Method 1: Desktop Application (Recommended)

**Windows/macOS/Linux**:
1. Visit https://anythingllm.com/download
2. Download the installer for your operating system
3. Run the installer and follow the setup wizard
4. Launch AnythingLLM from your applications

#### Method 2: Docker (Advanced Users)

```bash
# Pull the Docker image
docker pull mintplexlabs/anythingllm

# Run AnythingLLM container
docker run -d \
  --name anythingllm \
  -p 3001:3001 \
  -v anythingllm_data:/app/server/storage \
  -v anythingllm_models:/app/server/storage/models \
  mintplexlabs/anythingllm

# Access at http://localhost:3001
```

#### Method 3: From Source (Developers)

```bash
# Clone the repository
git clone https://github.com/Mintplex-Labs/anything-llm.git
cd anything-llm

# Install dependencies and build
yarn install
yarn build

# Start the application
yarn start
```

## Part 4: Configuring AnythingLLM with Ollama

Now let's connect AnythingLLM to your local Ollama instance.

### Initial Setup

1. **Launch AnythingLLM** - Open the application

2. **First-Time Setup Wizard**:
   - Click "Get Started"
   - Choose your language preference
   - Skip cloud service options (we're going offline!)

### Connecting to Ollama

1. **Navigate to Settings**:
   - Click the gear icon (⚙️) in the bottom left
   - Select "LLM Preference" from the sidebar

2. **Configure Ollama Connection**:
   - **LLM Provider**: Select "Ollama"
   - **Ollama Base URL**: `http://localhost:11434`
   - **Model**: Select your installed Dolphin model from the dropdown
   - Click "Save" or "Update"

3. **Verify Connection**:
   - AnythingLLM will test the connection
   - You should see a green checkmark if successful

### Troubleshooting Connection Issues

If AnythingLLM can't connect to Ollama:

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Should return JSON with your installed models

# If not running, start Ollama
# Linux:
sudo systemctl start ollama

# macOS/Windows:
# Restart from system tray or run:
ollama serve
```

## Part 5: Creating Your First Workspace

Workspaces in AnythingLLM organize your conversations and documents.

### Setting Up a Workspace

1. **Create New Workspace**:
   - Click "+ New Workspace" button
   - Name it (e.g., "General Chat", "Technical Research", "Writing")
   - Choose your Dolphin model
   - Set temperature (0.7 is balanced, higher = more creative)

2. **Configure Workspace Settings**:
   - **Temperature**: 0.7 (recommended default)
   - **Context Window**: Set based on your model's capacity
   - **Top P**: 0.9 (recommended)
   - **System Prompt**: Customize the AI's behavior (optional)

### Example System Prompts

**General Assistant**:
```
You are a helpful, knowledgeable AI assistant. Provide clear, accurate, and concise responses. When uncertain, acknowledge limitations.
```

**Technical Expert**:
```
You are an expert programmer and system administrator. Provide detailed technical explanations with code examples. Focus on best practices and security.
```

**Creative Writer**:
```
You are a creative writing assistant. Help with storytelling, character development, and prose improvement. Be imaginative and supportive.
```

## Part 6: Advanced Features

### Document Chat (RAG)

AnythingLLM can read and answer questions about your documents:

1. **Upload Documents**:
   - Click the document icon in your workspace
   - Upload PDF, TXT, DOCX, or MD files
   - AnythingLLM will process and embed the content

2. **Ask Questions**:
   - "What are the main points in this document?"
   - "Summarize the technical requirements"
   - "Find information about [specific topic]"

### Supported Document Types
- PDF files
- Text files (.txt)
- Markdown (.md)
- Word documents (.docx)
- Code files (.py, .js, .java, etc.)

### Embedding Models

For document chat, you'll need an embedding model:

```bash
# Install nomic-embed-text (recommended)
ollama pull nomic-embed-text

# Or use a smaller alternative
ollama pull mxbai-embed-large
```

Configure in AnythingLLM:
- Settings → Embedding Preference
- Provider: Ollama
- Model: nomic-embed-text

### Web Scraping (Offline Mode)

While web scraping requires internet, you can download pages offline:

1. Save web pages as HTML or PDF
2. Upload them to your workspace
3. Query the content without needing live internet

## Part 7: Optimizing Performance

### Hardware Optimization

**Enable GPU Acceleration (NVIDIA)**:

```bash
# Ollama automatically detects CUDA-capable GPUs
# Verify GPU is being used:
ollama run dolphin-mistral --verbose

# You should see GPU memory allocation in the output
```

**Adjust Model Parameters**:

```bash
# Run with custom context window
ollama run dolphin-mistral --ctx-size 4096

# Run with specific number of GPU layers
ollama run dolphin-mistral --n-gpu-layers 35
```

### Memory Management

**Linux**: Monitor memory usage
```bash
# Watch memory in real-time
watch -n 1 free -h

# Check Ollama's memory usage
ps aux | grep ollama
```

**Windows**: Use Task Manager
- Press Ctrl+Shift+Esc
- Look for "ollama" process
- Monitor memory and GPU usage

### Model Selection Tips

| Use Case | Recommended Model | RAM Needed | Performance |
|----------|------------------|------------|-------------|
| Quick questions | dolphin-phi | 8GB | Fast |
| General use | dolphin-mistral | 16GB | Balanced |
| Complex tasks | dolphin-mixtral | 32GB | Best quality |
| Technical work | dolphin2.5-mixtral | 32GB | High accuracy |

## Part 8: Best Practices for Offline Use

### Prompt Engineering Tips

**Be Specific**:
```
❌ "Tell me about networking"
✅ "Explain how TCP/IP three-way handshake works with a diagram"
```

**Provide Context**:
```
❌ "Fix this code"
✅ "This Python function should validate email addresses but returns False for valid emails. Please fix it: [code]"
```

**Use System Prompts**:
Set a clear role for consistent behavior across sessions.

### Maintaining Your System

**Regular Updates**:
```bash
# Update Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Update models (check for new versions)
ollama pull dolphin-mistral

# Update AnythingLLM
# Download latest version from website or use built-in updater
```

**Disk Space Management**:
```bash
# Check model storage
ollama list

# Remove unused models
ollama rm old-model-name

# Clear conversation history (in AnythingLLM)
# Settings → Privacy → Clear Chat History
```

### Backup Your Setup

**Backup Ollama Models**:
```bash
# Models are stored in:
# Linux: /usr/share/ollama/.ollama/models
# macOS: ~/.ollama/models
# Windows: C:\Users\<username>\.ollama\models

# Create backup
tar -czf ollama-models-backup.tar.gz ~/.ollama/models
```

**Backup AnythingLLM Data**:
```bash
# Desktop app data location:
# Linux: ~/.config/anythingllm-desktop
# macOS: ~/Library/Application Support/anythingllm-desktop  
# Windows: C:\Users\<username>\AppData\Roaming\anythingllm-desktop

# Create backup
tar -czf anythingllm-backup.tar.gz ~/.config/anythingllm-desktop
```

## Part 9: Troubleshooting Common Issues

### Ollama Won't Start

**Issue**: Ollama service fails to start

**Solution**:
```bash
# Check if port 11434 is in use
sudo netstat -tulpn | grep 11434

# Kill conflicting process
sudo kill -9 <PID>

# Restart Ollama
sudo systemctl restart ollama
```

### Model Download Fails

**Issue**: Model download interrupted or fails

**Solution**:
```bash
# Remove partial download
ollama rm dolphin-mistral

# Try download again with verbose output
ollama pull dolphin-mistral --verbose

# Check disk space
df -h
```

### Slow Performance

**Issue**: Responses are very slow

**Solutions**:
1. **Use a smaller model**: Switch from mixtral to mistral
2. **Close other applications**: Free up RAM
3. **Check GPU usage**: Ensure GPU acceleration is working
4. **Reduce context window**: Lower the context size in settings

```bash
# Monitor system resources
htop  # Linux
# Task Manager on Windows
```

### AnythingLLM Can't Connect

**Issue**: "Failed to connect to Ollama"

**Checklist**:
- [ ] Ollama is running: `curl http://localhost:11434/api/tags`
- [ ] Correct URL in settings: `http://localhost:11434`
- [ ] Firewall not blocking: Temporarily disable and test
- [ ] Model is downloaded: `ollama list`

**Fix**:
```bash
# Restart Ollama service
sudo systemctl restart ollama

# Test connection manually
curl http://localhost:11434/api/tags

# Check Ollama logs
journalctl -u ollama -f
```

### Out of Memory Errors

**Issue**: System crashes or model fails to load

**Solutions**:
1. **Switch to smaller model**:
```bash
ollama pull dolphin-phi  # Only 2.7B parameters
```

2. **Increase swap space** (Linux):
```bash
# Create 16GB swap file
sudo fallocate -l 16G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

3. **Close other applications**: Free up system resources

## Part 10: Use Cases and Examples

### Programming Assistant

**Prompt**:
```
I need a Python function that reads a CSV file and returns a dictionary where keys are values from the first column and values are lists of remaining column values. Include error handling.
```

**Workspace Setup**:
- Model: dolphin-mistral or dolphin-mixtral
- Temperature: 0.3 (more deterministic for code)
- System Prompt: "You are an expert programmer. Provide clean, well-commented code with error handling."

### Research and Analysis

**Prompt**:
```
I'm uploading a research paper about quantum computing. Please:
1. Summarize the main findings
2. Explain the methodology
3. List practical applications mentioned
4. Identify any limitations discussed
```

**Workspace Setup**:
- Upload research papers as PDFs
- Model: dolphin-mixtral (better comprehension)
- Temperature: 0.5
- Enable document chat with nomic-embed-text

### Creative Writing

**Prompt**:
```
Help me develop a character for my sci-fi novel:
- Name: Dr. Sarah Chen
- Role: Xenobiologist on Mars colony
- Conflict: Discovers evidence of ancient Martian life
- Personality: [your input]

Create a character profile with background, motivations, and potential story arcs.
```

**Workspace Setup**:
- Model: dolphin-mixtral (better creativity)
- Temperature: 0.9 (higher creativity)
- System Prompt: "You are a creative writing coach specializing in science fiction."

### Technical Documentation

**Prompt**:
```
Convert this technical specification into user-friendly documentation for non-technical staff. Include:
- Overview in plain language
- Step-by-step instructions
- Common troubleshooting
- FAQ section

[Paste technical spec]
```

**Workspace Setup**:
- Model: dolphin-mistral
- Temperature: 0.6
- Upload existing documentation for context

## Part 11: Privacy and Security

### Why Offline Matters

**Data Privacy**:
- No conversation logs sent to external servers
- No user tracking or analytics
- Complete control over your data

**Compliance**:
- GDPR compliant (data stays local)
- HIPAA considerations (healthcare)
- SOC 2 / corporate security requirements

**Intellectual Property**:
- Safe to discuss proprietary information
- No risk of data training on your inputs
- Suitable for sensitive business use

### Security Best Practices

1. **Keep Software Updated**:
   - Regular Ollama updates
   - AnythingLLM security patches
   - OS security updates

2. **Access Control**:
   - Use firewalls to block external access to port 11434
   - Consider user authentication in AnythingLLM
   - Don't expose services to the internet

3. **Data Encryption**:
   - Use full disk encryption
   - Encrypt backups
   - Secure physical access to servers

4. **Network Isolation**:
```bash
# Bind Ollama to localhost only (Linux)
# Edit: /etc/systemd/system/ollama.service
Environment="OLLAMA_HOST=127.0.0.1:11434"

# Restart service
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

## Part 12: Advanced Configuration

### Custom Model Parameters

Create a custom Modelfile for fine-tuned behavior:

```bash
# Create Modelfile
cat > Dolphin-Custom <<EOF
FROM dolphin-mistral

# Set parameters
PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 4096

# Custom system prompt
SYSTEM You are a security-focused AI assistant specializing in cybersecurity and penetration testing. Provide detailed, accurate technical guidance.
EOF

# Create custom model
ollama create dolphin-security -f Dolphin-Custom

# Use your custom model
ollama run dolphin-security
```

### Environment Variables

Configure Ollama behavior with environment variables:

```bash
# Set model storage location
export OLLAMA_MODELS=/path/to/models

# Set number of parallel requests
export OLLAMA_NUM_PARALLEL=2

# Set max loaded models
export OLLAMA_MAX_LOADED_MODELS=2

# Enable debug logging
export OLLAMA_DEBUG=1

# Restart Ollama to apply
sudo systemctl restart ollama
```

### API Integration

Use Ollama's API for custom integrations:

```python
# Python example
import requests
import json

def query_ollama(prompt, model="dolphin-mistral"):
    url = "http://localhost:11434/api/generate"
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }
    
    response = requests.post(url, json=data)
    return response.json()["response"]

# Use it
result = query_ollama("Explain docker containers")
print(result)
```

```bash
# Curl example
curl http://localhost:11434/api/generate -d '{
  "model": "dolphin-mistral",
  "prompt": "Why is the sky blue?",
  "stream": false
}'
```

### Multi-Model Setup

Run different models for different purposes:

```bash
# Install multiple models
ollama pull dolphin-phi        # Fast responses
ollama pull dolphin-mistral    # Balanced
ollama pull dolphin-mixtral    # Best quality
ollama pull codellama          # Code generation
ollama pull llava              # Vision tasks

# Create workspaces in AnythingLLM for each
```

## Part 13: Performance Benchmarks

### Response Time Expectations

**dolphin-phi (2.7B)** on 16GB RAM system:
- Simple query: 1-3 seconds
- Complex analysis: 5-15 seconds
- Code generation: 3-10 seconds

**dolphin-mistral (7B)** on 16GB RAM system:
- Simple query: 3-8 seconds
- Complex analysis: 15-30 seconds
- Code generation: 10-20 seconds

**dolphin-mixtral (8x7B)** on 32GB RAM + GPU:
- Simple query: 2-5 seconds (with GPU)
- Complex analysis: 10-25 seconds
- Code generation: 8-18 seconds

### Optimization Results

**With GPU acceleration** (NVIDIA RTX 3060):
- 5-10x faster inference
- Better for interactive conversations
- Required for larger models

**CPU-only performance**:
- Suitable for batch processing
- Acceptable for non-real-time use
- Consider smaller models

## Part 14: Comparison with Cloud Services

### Feature Comparison

| Feature | Offline Setup | ChatGPT Plus | Claude Pro |
|---------|--------------|--------------|------------|
| Monthly Cost | $0 (after hardware) | $20/month | $20/month |
| Privacy | 100% private | Data sent to OpenAI | Data sent to Anthropic |
| Internet Required | No | Yes | Yes |
| Response Speed | Varies by hardware | Fast | Fast |
| Model Updates | Manual | Automatic | Automatic |
| Censorship | None (Dolphin) | Yes | Yes |
| API Access | Free (local) | Pay per token | Pay per token |
| Customization | Full control | Limited | Limited |

### Cost Analysis

**Year 1**:
- Hardware (if needed): $500-2000
- Software: $0
- **Total**: $500-2000

**Cloud Alternative (Year 1)**:
- Subscription: $240 ($20/mo × 12)
- API usage: $100-500 (varies)
- **Total**: $340-740

**Break-even**: 12-24 months depending on usage and existing hardware.

## Conclusion

You now have a fully functional offline LLM system that respects your privacy while providing powerful AI assistance. This setup gives you:

✅ Complete data privacy and control
✅ Zero recurring costs after initial setup
✅ Unlimited usage without API restrictions
✅ Customizable models and behavior
✅ Works completely offline
✅ Professional-grade AI capabilities

### Next Steps

1. **Experiment with different models** - Try various Dolphin versions
2. **Create specialized workspaces** - Organize by task type
3. **Upload your documents** - Enable RAG for your personal knowledge base
4. **Customize system prompts** - Tune the AI for your specific needs
5. **Explore the API** - Integrate with your own applications

### Additional Resources

- **Ollama Documentation**: https://github.com/ollama/ollama
- **AnythingLLM Docs**: https://docs.anythingllm.com
- **Dolphin Models**: https://huggingface.co/cognitivecomputations
- **Community Support**: r/LocalLLaMA, r/Ollama

### Need Help?

If you run into issues during setup:

1. Check the troubleshooting section above
2. Consult Ollama GitHub issues
3. Join the AnythingLLM Discord community
4. Post questions on r/LocalLLaMA

---

*This guide was created for Pacific Northwest Computers. For professional IT consulting, cybersecurity services, or help setting up local AI systems for your business, visit our website or contact us.*

**Document Version**: 1.0  
**Last Updated**: November 2025  
**Compatible With**: Ollama 0.1.x+, AnythingLLM 1.0+, Dolphin 2.5+

---

## Frequently Asked Questions

**Q: Can I use this setup for commercial purposes?**  
A: Yes! Dolphin models are open-source and can be used commercially. Check specific model licenses on HuggingFace.

**Q: How much does this cost?**  
A: After initial hardware investment, there are zero recurring costs. No subscriptions or API fees.

**Q: Is this as good as ChatGPT?**  
A: For many tasks, yes. Larger Dolphin models (mixtral) perform comparably to GPT-3.5. They won't match GPT-4, but the privacy and cost benefits are significant.

**Q: Can I run this on a laptop?**  
A: Yes! A laptop with 16GB RAM can run smaller models (phi, mistral-7b) effectively. Performance varies by CPU.

**Q: Do I need a GPU?**  
A: No, but it helps significantly. CPU-only inference works but is slower. NVIDIA GPUs provide the best acceleration.

**Q: Can I access this from multiple devices?**  
A: Yes! Set up Ollama on a server and configure AnythingLLM on multiple devices to connect to it. Ensure proper network security.

**Q: How often should I update?**  
A: Check for updates monthly. Ollama and AnythingLLM release improvements regularly. Model updates are less frequent.

**Q: Can I use other models besides Dolphin?**  
A: Absolutely! Ollama supports Llama, Mistral, CodeLlama, Vicuna, and many others. Dolphin is recommended for its uncensored nature.

**Q: Is this legal?**  
A: Yes. Running open-source models locally is completely legal. Dolphin uses properly licensed base models.

**Q: Can I train or fine-tune models?**  
A: While this guide focuses on inference, you can fine-tune models using tools like Axolotl or LLaMA Factory, then run them in Ollama.

---

**Happy local AI adventures! 🚀**
