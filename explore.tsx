import React, { useState, useEffect, useRef } from 'react';
import {
  StyleSheet,
  View,
  Text,
  ActivityIndicator,
  ScrollView,
  Pressable,
  Animated,
  Easing,
  useColorScheme,
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';
import * as Crypto from 'expo-crypto';
import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';
import Svg, { G, Path } from 'react-native-svg';
import { Ionicons } from '@expo/vector-icons';

// ---------------------------------------------------------------------------
// Theme Definitions (Dark & Light) with Purple Primary Button
// ---------------------------------------------------------------------------
const themes = {
  light: {
    background: '#f5f5f5',
    text: '#333',
    primary: '#6C5CE7', // purple button
    card: '#ffffff',
    danger: '#F44336',
    success: '#4CAF50',
  },
  dark: {
    background: '#2D3436',
    text: '#FFFFFF',
    primary: '#6C5CE7', // purple button remains the same
    card: '#404040',
    danger: '#F44336',
    success: '#4CAF50',
  }
};

// ---------------------------------------------------------------------------
// Config & Interfaces
// ---------------------------------------------------------------------------
const VIRUSTOTAL_API_KEY =
  'eb9cd3d7cf4ecf107ca521f4081a2f5429955148b989c0fa09121a0635581cbc'; // Replace with your API key

interface FileResult {
  name: string;
  size: number;
  uri: string;
}

interface ScanResult {
  stats: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
  };
  vendors: Array<{
    vendor: string;
    result: string;
    category: string;
  }>;
}

// ---------------------------------------------------------------------------
// Animated Pie Chart Code
// ---------------------------------------------------------------------------

// Helper: convert polar to Cartesian coordinates
const polarToCartesian = (
  centerX: number,
  centerY: number,
  radius: number,
  angleInDegrees: number
) => {
  const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180.0;
  return {
    x: centerX + radius * Math.cos(angleInRadians),
    y: centerY + radius * Math.sin(angleInRadians),
  };
};

// Helper: describe an SVG arc from startAngle to endAngle
const describeArc = (
  x: number,
  y: number,
  radius: number,
  startAngle: number,
  endAngle: number
) => {
  const start = polarToCartesian(x, y, radius, endAngle);
  const end = polarToCartesian(x, y, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? '0' : '1';
  return [
    'M', start.x, start.y,
    'A', radius, radius, 0, largeArcFlag, 0, end.x, end.y,
    'L', x, y, 'Z'
  ].join(' ');
};

interface SliceData {
  value: number;
  color: string;
}

interface AnimatedPieChartProps {
  data: SliceData[];
  width?: number;
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
}

const AnimatedPieChart: React.FC<AnimatedPieChartProps> = ({
  data,
  width = 250,
  height = 250,
  innerRadius = 0,
  outerRadius = 100,
}) => {
  const [progress, setProgress] = useState(0);
  const animation = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    const listenerId = animation.addListener(({ value }) => setProgress(value));
    Animated.timing(animation, {
      toValue: 1,
      duration: 1500,
      easing: Easing.out(Easing.ease),
      useNativeDriver: false,
    }).start();
    return () => animation.removeListener(listenerId);
  }, [animation]);

  const total = data.reduce((sum, item) => sum + item.value, 0);
  let cumulativeAngle = 0;
  return (
    <Svg width={width} height={height}>
      {/* Rotate -90 so the chart starts at top */}
      <G rotation="-90" origin={`${width / 2}, ${height / 2}`}>
        {data.map((slice, index) => {
          const sliceAngle = (slice.value / total) * 360;
          const animatedEndAngle = cumulativeAngle + sliceAngle * progress;
          const path = describeArc(
            width / 2,
            height / 2,
            outerRadius,
            cumulativeAngle,
            animatedEndAngle
          );
          cumulativeAngle += sliceAngle;
          return <Path key={`slice-${index}`} d={path} fill={slice.color} />;
        })}
      </G>
    </Svg>
  );
};

// ---------------------------------------------------------------------------
// Animated Vendor Card Component
// ---------------------------------------------------------------------------
const AnimatedVendorCard: React.FC<{
  vendor: ScanResult['vendors'][0];
  delay: number;
}> = ({ vendor, delay }) => {
  const fadeAnim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 600,
      delay,
      useNativeDriver: true,
    }).start();
  }, [fadeAnim, delay]);
  
  return (
    <Animated.View style={{ opacity: fadeAnim, marginBottom: 8 }}>
      <View
        style={[
          styles.vendorCard,
          {
            backgroundColor:
              vendor.category === 'malicious' ? '#ffebee' : '#e8f5e9',
          },
        ]}
      >
        <View style={styles.vendorHeader}>
          <Text style={styles.vendorName}>{vendor.vendor}</Text>
          <Ionicons
            name="shield-checkmark"
            size={20}
            color={vendor.category === 'malicious' ? '#F44336' : '#4CAF50'}
          />
        </View>
        <Text style={styles.vendorResult}>
          Result: {vendor.result || 'Clean'}
        </Text>
        <Text style={styles.vendorCategory}>
          Category: {vendor.category}
        </Text>
      </View>
    </Animated.View>
  );
};

// ---------------------------------------------------------------------------
// Main File Scanner Screen with Dark/Light Theme & Purple Buttons
// ---------------------------------------------------------------------------
export default function FileScannerScreen() {
  const colorScheme = useColorScheme() || 'light';
  const theme = themes[colorScheme];

  const [file, setFile] = useState<FileResult | null>(null);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Open file picker
  const pickDocument = async () => {
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: false,
      });
      if (result.assets && result.assets[0]) {
        const selectedFile = result.assets[0];
        setFile({
          name: selectedFile.name,
          size: selectedFile.size || 0,
          uri: selectedFile.uri,
        });
        setError('');
        generateHash(selectedFile.uri);
      }
    } catch (err) {
      setError('Error picking file: ' + (err as Error).message);
    }
  };

  // Generate SHA256 hash of the file
  const generateHash = async (fileUri: string) => {
    try {
      setLoading(true);
      const response = await fetch(fileUri);
      const fileData = await response.blob();
      const reader = new FileReader();
      reader.onload = async () => {
        const hash = await Crypto.digestStringAsync(
          Crypto.CryptoDigestAlgorithm.SHA256,
          reader.result as string
        );
        checkVirusTotal(hash);
      };
      reader.readAsText(fileData);
    } catch (err) {
      setError('Error generating hash: ' + (err as Error).message);
      setLoading(false);
    }
  };

  // Query VirusTotal using the hash (with caching)
  const checkVirusTotal = async (hash: string) => {
    try {
      const cachedResult = await AsyncStorage.getItem(hash);
      if (cachedResult) {
        setResults(JSON.parse(cachedResult));
        setLoading(false);
        return;
      }
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        { headers: { 'x-apikey': VIRUSTOTAL_API_KEY } }
      );
      const analysisResults =
        response.data.data.attributes.last_analysis_results;
      const stats = response.data.data.attributes.last_analysis_stats;
      const resultData: ScanResult = {
        stats,
        vendors: Object.entries(analysisResults).map(
          ([vendor, data]: [string, any]) => ({
            vendor,
            result: data.result || 'Clean',
            category: data.category,
          })
        ),
      };
      await AsyncStorage.setItem(hash, JSON.stringify(resultData));
      setResults(resultData);
    } catch (err) {
      setError(
        'VirusTotal Error: ' +
          ((err as any).response?.data?.error?.message ||
            (err as Error).message)
      );
    } finally {
      setLoading(false);
    }
  };

  // Overall severity (based on stats)
  const getSeverityLevel = () => {
    if (!results) return 'Unknown';
    const totalBad = results.stats.malicious + results.stats.suspicious;
    if (totalBad === 0) return 'Clean';
    if (totalBad <= 2) return 'Low Risk';
    if (totalBad <= 5) return 'Moderate Risk';
    if (totalBad <= 10) return 'High Risk';
    return 'Critical Risk';
  };

  // Prepare animated pie chart data if results are available
  const pieData = results
    ? [
        { value: results.stats.malicious, color: theme.danger },
        { value: results.stats.suspicious, color: '#FFC107' },
        { value: results.stats.harmless, color: theme.success },
        { value: results.stats.undetected, color: '#9E9E9E' },
      ]
    : [];

  return (
    <ScrollView
      contentContainerStyle={[
        styles.container,
        { backgroundColor: theme.background },
      ]}
    >
      <Text style={[styles.title, { color: theme.text }]}>
        VirusTotal File Scanner
      </Text>

      <View style={styles.buttonContainer}>
        <Pressable
          style={({ pressed }) => [
            styles.button,
            { backgroundColor: theme.primary, opacity: pressed || loading ? 0.6 : 1 },
          ]}
          onPress={pickDocument}
          disabled={loading}
        >
          <Text style={[styles.buttonText, { color: '#fff' }]}>
            {file ? 'Reselect File' : 'Select File'}
          </Text>
        </Pressable>
      </View>

      {file && (
        <View style={[styles.fileInfo, { backgroundColor: theme.card }]}>
          <Text style={{ color: theme.text }}>Selected File: {file.name}</Text>
          <Text style={{ color: theme.text }}>
            Size: {(file.size / 1024).toFixed(2)} KB
          </Text>
        </View>
      )}

      {loading && <ActivityIndicator size="large" style={styles.loader} />}

      {error ? (
        <Text style={styles.error}>{error}</Text>
      ) : results ? (
        <View style={[styles.results, { backgroundColor: theme.card }]}>
          <Text
            style={[
              styles.severity,
              { color: severityColor(getSeverityLevel()) },
            ]}
          >
            Severity: {getSeverityLevel()}
          </Text>

          {/* Animated Pie Chart Visualization */}
          <View style={styles.pieChartContainer}>
            <AnimatedPieChart
              data={pieData}
              width={200}
              height={200}
              outerRadius={90}
            />
            <Text style={[styles.pieChartLabel, { color: theme.text }]}>
              Scan Stats
            </Text>
          </View>

          <View style={styles.stats}>
            <Text style={{ color: theme.text }}>
              Malicious: {results.stats.malicious}
            </Text>
            <Text style={{ color: theme.text }}>
              Suspicious: {results.stats.suspicious}
            </Text>
            <Text style={{ color: theme.text }}>
              Undetected: {results.stats.undetected}
            </Text>
            <Text style={{ color: theme.text }}>
              Harmless: {results.stats.harmless}
            </Text>
          </View>

          <Text style={[styles.subTitle, { color: theme.text }]}>
            Vendor Results:
          </Text>
          {results.vendors.map((vendor, index) => (
            <AnimatedVendorCard key={index} vendor={vendor} delay={index * 150} />
          ))}
        </View>
      ) : null}
    </ScrollView>
  );
}

// ---------------------------------------------------------------------------
// Helper: Determine severity color based on level
// ---------------------------------------------------------------------------
const severityColor = (level: string) => {
  switch (level) {
    case 'Clean':
      return '#4CAF50';
    case 'Low Risk':
      return '#FFC107';
    case 'Moderate Risk':
      return '#FF9800';
    case 'High Risk':
      return '#F44336';
    case 'Critical Risk':
      return '#B71C1C';
    default:
      return '#9E9E9E';
  }
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------
const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    padding: 20,
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  buttonContainer: {
    marginVertical: 10,
    width: '100%',
    borderRadius: 8,
    overflow: 'hidden',
  },
  button: {
    padding: 15,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonText: {
    fontWeight: '600',
    fontSize: 16,
  },
  fileInfo: {
    marginVertical: 15,
    padding: 10,
    borderRadius: 5,
    width: '100%',
  },
  loader: {
    marginVertical: 20,
  },
  error: {
    color: '#F44336',
    marginVertical: 10,
    textAlign: 'center',
  },
  results: {
    marginTop: 20,
    width: '100%',
    padding: 15,
    borderRadius: 8,
  },
  severity: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    textAlign: 'center',
  },
  pieChartContainer: {
    alignItems: 'center',
    marginVertical: 20,
  },
  pieChartLabel: {
    marginTop: 10,
    fontSize: 16,
    fontWeight: '600',
  },
  stats: {
    marginBottom: 15,
    padding: 10,
    borderRadius: 5,
    elevation: 2,
  },
  subTitle: {
    fontSize: 18,
    fontWeight: '600',
    marginVertical: 10,
    textAlign: 'center',
  },
  vendorCard: {
    padding: 10,
    borderRadius: 5,
  },
  vendorHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  vendorName: {
    fontWeight: '500',
    color: '#2c3e50',
  },
  vendorResult: {
    fontSize: 14,
    marginBottom: 2,
  },
  vendorCategory: {
    fontSize: 12,
    fontStyle: 'italic',
  },
});
