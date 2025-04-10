# 📱 VirusTotal Mobile Dashboard

A React Native app that allows users to either **upload a file** or **query a SHA256 hash** to VirusTotal's API and visualize the detection results in a beautiful **pie chart**.

## 🚀 Features

- 📁 Upload any file to VirusTotal and get a real-time scan report
- 🔎 Query files directly using their SHA256 hash
- 📊 Visualize detection statistics: Malicious, Suspicious, Undetected, and Timeout
- 💡 Clean UI built with React Native Paper and chart rendering with react-native-chart-kit
- ⚙️ Fully animated and mobile-friendly

---

## 🧠 Architecture & Workflow

```mermaid
graph TD
  A[User] -->|Upload File| B[Document Picker]
  B --> C[Send to VirusTotal Upload API]
  C --> D[Receive File ID]
  D --> E[Query VirusTotal Report API]
  E --> F[Parse last_analysis_stats]
  F --> G[Display Result + Pie Chart]
  A -->|Enter SHA256| H[Query VirusTotal Report API (SHA)]
  H --> F
```
