import React, { useState, useEffect, useRef } from 'react';
import {
  StyleSheet,
  View,
  Text,
  ActivityIndicator,
  Pressable,
  TextInput,
  Animated,
  Easing,
  ScrollView,
  useColorScheme
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';
import Svg, { G, Path } from 'react-native-svg';

const VIRUSTOTAL_API_KEY = 'eb9cd3d7cf4ecf107ca521f4081a2f5429955148b989c0fa09121a0635581cbc';

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

interface ThemeColors {
  background: string;
  text: string;
  primary: string;
  card: string;
  danger: string;
  success: string;
}

const themes: { light: ThemeColors; dark: ThemeColors } = {
  light: {
    background: '#FFFFFF',
    text: '#2D3436',
    primary: '#6C5CE7',
    card: '#F8F9FA',
    danger: '#D63031',
    success: '#00B894',
  },
  dark: {
    background: '#2D3436',
    text: '#FFFFFF',
    primary: '#A8A4FF',
    card: '#404040',
    danger: '#FF7675',
    success: '#55EFC4',
  }
};

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
  const d = [
    'M',
    start.x,
    start.y,
    'A',
    radius,
    radius,
    0,
    largeArcFlag,
    0,
    end.x,
    end.y,
    'L',
    x,
    y,
    'Z',
  ].join(' ');
  return d;
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
  // Animation from 0 to 1
  const [progress, setProgress] = useState(0);
  const animation = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    const listenerId = animation.addListener(({ value }) => {
      setProgress(value);
    });

    Animated.timing(animation, {
      toValue: 1,
      duration: 1500,
      easing: Easing.out(Easing.ease),
      useNativeDriver: false,
    }).start();

    return () => {
      animation.removeListener(listenerId);
    };
  }, [animation]);

  const total = data.reduce((sum, item) => sum + item.value, 0);
  let cumulativeAngle = 0;

  return (
    <Svg width={width} height={height}>
      {/* Rotate -90 so the chart starts from the top */}
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
const StatBox: React.FC<{ 
  value: number; 
  label: string; 
  color: string; 
  theme: ThemeColors 
}> = ({ value, label, color, theme }) => (
  <View style={[styles.statBox, { backgroundColor: theme.card }]}>
    <Text style={[styles.statValue, { color }]}>{value}</Text>
    <Text style={[styles.statLabel, { color: theme.text }]}>{label}</Text>
  </View>
);

const VendorCard: React.FC<{ 
  vendor: ScanResult['vendors'][0]; 
  theme: ThemeColors 
}> = ({ vendor, theme }) => (
  <View style={[styles.vendorCard, { backgroundColor: theme.card }]}>
    <View style={styles.vendorHeader}>
      <Text style={[styles.vendorName, { color: theme.text }]}>{vendor.vendor}</Text>
      <View style={[
        styles.statusDot,
        { backgroundColor: vendor.category === 'malicious' ? theme.danger : theme.success }
      ]} />
    </View>
    <Text style={[styles.vendorResult, { color: theme.text }]}>
      {vendor.result || 'No issues found'}
    </Text>
    <Text style={[styles.vendorCategory, { color: '#888' }]}>
      {vendor.category}
    </Text>
  </View>
);

const AnimatedVendorCard: React.FC<{ vendor: ScanResult['vendors'][0]; theme: ThemeColors; delay: number }> = ({ vendor, theme, delay }) => {
  const fadeAnim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 600,
      delay: delay,
      useNativeDriver: true,
    }).start();
  }, [fadeAnim, delay]);

  return (
    <Animated.View style={{ opacity: fadeAnim }}>
      <VendorCard vendor={vendor} theme={theme} />
    </Animated.View>
  );
};

const severityColor = (level: string, theme: ThemeColors): string => {
  switch(level) {
    case 'Clean': return theme.success;
    case 'Low Risk': return '#FFC107';
    case 'Moderate Risk': return '#FF9800';
    case 'High Risk': return theme.danger;
    case 'Critical Risk': return '#B71C1C';
    default: return '#999';
  }
};

const HomeScreen: React.FC = () => {
  const colorScheme = useColorScheme() || 'light';
  const theme = themes[colorScheme];
  const [shaInput, setShaInput] = useState<string>('');
  const [shaResults, setShaResults] = useState<ScanResult | null>(null);
  const [shaLoading, setShaLoading] = useState<boolean>(false);
  const [shaError, setShaError] = useState<string>('');
  const progressAnim = useRef(new Animated.Value(0)).current;

  const animateProgress = (toValue: number) => {
    Animated.timing(progressAnim, {
      toValue,
      duration: 500,
      easing: Easing.out(Easing.ease),
      useNativeDriver: false
    }).start();
  };

  const checkHash = async () => {
    if (!shaInput.match(/^[a-fA-F0-9]{64}$/)) {
      setShaError('Invalid SHA256 format');
      animateProgress(0);
      return;
    }

    try {
      setShaLoading(true);
      setShaError('');
      animateProgress(0.3);

      const cachedResult = await AsyncStorage.getItem(shaInput);
      if (cachedResult) {
        setShaResults(JSON.parse(cachedResult));
        animateProgress(1);
        return;
      }

      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${shaInput}`,
        { headers: { 'x-apikey': VIRUSTOTAL_API_KEY } }
      );

      const analysisResults = response.data.data.attributes.last_analysis_results;
      const stats = response.data.data.attributes.last_analysis_stats;

      const resultData: ScanResult = {
        stats,
        vendors: Object.entries(analysisResults).map(([vendor, data]: [string, any]) => ({
          vendor,
          result: data.result || 'Clean',
          category: data.category,
        })),
      };

      await AsyncStorage.setItem(shaInput, JSON.stringify(resultData));
      setShaResults(resultData);
      animateProgress(1);
    } catch (err) {
      setShaError(`VirusTotal Error: ${(err as any).response?.data?.error?.message || (err as Error).message}`);
      animateProgress(0);
    } finally {
      setShaLoading(false);
    }
  };

  const getSeverityLevel = (): string => {
    if (!shaResults) return 'Unknown';
    const totalBad = shaResults.stats.malicious + shaResults.stats.suspicious;
    if (totalBad === 0) return 'Clean';
    if (totalBad <= 2) return 'Low Risk';
    if (totalBad <= 5) return 'Moderate Risk';
    if (totalBad <= 10) return 'High Risk';
    return 'Critical Risk';
  };

  const pieData = shaResults
    ? [
        { value: shaResults.stats.malicious, color: theme.danger },
        { value: shaResults.stats.suspicious, color: '#FFC107' },
        { value: shaResults.stats.harmless, color: theme.success },
        { value: shaResults.stats.undetected, color: '#999' },
      ]
    : [];

  return (
    <View style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <Text style={[styles.title, { color: theme.text }]}>🔒 Hash Security Check</Text>

        <View style={styles.inputContainer}>
          <TextInput
            style={[
              styles.input,
              { 
                backgroundColor: theme.card,
                borderColor: theme.primary,
                color: theme.text
              }
            ]}
            placeholder="Enter SHA256 hash"
            placeholderTextColor="#999"
            value={shaInput}
            onChangeText={setShaInput}
            autoCapitalize="none"
            autoCorrect={false}
          />
          <Ionicons 
            name="search" 
            size={24} 
            color={theme.primary} 
            style={styles.searchIcon} 
          />
        </View>

        <Pressable
          style={({ pressed }) => [
            styles.button,
            { 
              backgroundColor: theme.primary,
              opacity: pressed || shaLoading ? 0.8 : 1
            }
          ]}
          onPress={checkHash}
          disabled={shaLoading}
        >
          <Text style={styles.buttonText}>
            {shaLoading ? 'Analyzing...' : 'Check Security'}
          </Text>
          {shaLoading && <ActivityIndicator color="white" style={styles.loadingIcon} />}
        </Pressable>

        <ProgressBar progress={progressAnim} theme={theme} />

        {shaError ? (
          <View style={[styles.errorCard, { backgroundColor: theme.danger }]}>
            <Ionicons name="warning" size={24} color="white" />
            <Text style={styles.errorText}>{shaError}</Text>
          </View>
        ) : shaResults && (
          <Animated.View 
            style={[
              styles.resultCard, 
              { backgroundColor: theme.card },
              { opacity: progressAnim }
            ]}
          >
            <View style={styles.severityHeader}>
              <Text style={[styles.severityText, { color: theme.text }]}>
                {getSeverityLevel()}
              </Text>
              <Ionicons 
                name="shield-checkmark" 
                size={32} 
                color={severityColor(getSeverityLevel(), theme)} 
              />
            </View>

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

            {/* Stats Grid */}
            <View style={styles.statsGrid}>
              <StatBox 
                value={shaResults.stats.malicious}
                label="Malicious"
                color={theme.danger}
                theme={theme}
              />
              <StatBox 
                value={shaResults.stats.suspicious}
                label="Suspicious"
                color="#FFC107"
                theme={theme}
              />
              <StatBox 
                value={shaResults.stats.harmless}
                label="Harmless"
                color={theme.success}
                theme={theme}
              />
              <StatBox 
                value={shaResults.stats.undetected}
                label="Undetected"
                color="#999"
                theme={theme}
              />
            </View>

            <Text style={[styles.subTitle, { color: theme.text }]}>
              Vendor Analysis Results
            </Text>
            {shaResults.vendors.map((vendor, index) => (
              <AnimatedVendorCard 
                key={index} 
                vendor={vendor} 
                theme={theme} 
                delay={index * 150} // stagger fade-in
              />
            ))}
          </Animated.View>
        )}
      </ScrollView>
    </View>
  );
};

const ProgressBar: React.FC<{ progress: Animated.Value; theme: ThemeColors }> = ({ progress, theme }) => (
  <View style={[styles.progressContainer, { backgroundColor: theme.card }]}>
    <Animated.View 
      style={[
        styles.progressBar,
        { 
          backgroundColor: theme.primary,
          width: progress.interpolate({
            inputRange: [0, 1],
            outputRange: ['0%', '100%']
          })
        }
      ]}
    />
  </View>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
  },
  scrollContent: {
    paddingBottom: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: '800',
    marginBottom: 30,
    textAlign: 'center',
  },
  inputContainer: {
    position: 'relative',
    marginBottom: 20,
  },
  input: {
    height: 50,
    borderWidth: 2,
    borderRadius: 12,
    paddingHorizontal: 20,
    fontSize: 16,
  },
  searchIcon: {
    position: 'absolute',
    right: 20,
    top: 13,
  },
  button: {
    padding: 18,
    borderRadius: 12,
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 5,
  },
  buttonText: {
    color: 'white',
    fontWeight: '600',
    fontSize: 16,
    marginRight: 10,
  },
  loadingIcon: {
    marginLeft: 10,
  },
  progressContainer: {
    height: 8,
    borderRadius: 4,
    marginVertical: 20,
    overflow: 'hidden',
  },
  progressBar: {
    height: '100%',
    borderRadius: 4,
  },
  errorCard: {
    padding: 16,
    borderRadius: 12,
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: 10,
  },
  errorText: {
    color: 'white',
    marginLeft: 10,
    fontSize: 14,
  },
  resultCard: {
    borderRadius: 16,
    padding: 20,
    marginTop: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 6,
    elevation: 3,
  },
  severityHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  severityText: {
    fontSize: 22,
    fontWeight: '700',
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  statBox: {
    width: '48%',
    padding: 16,
    borderRadius: 12,
    marginBottom: 15,
    alignItems: 'center',
  },
  statValue: {
    fontSize: 24,
    fontWeight: '800',
    marginBottom: 5,
  },
  statLabel: {
    fontSize: 14,
    fontWeight: '600',
    opacity: 0.8,
  },
  subTitle: {
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 15,
  },
  vendorCard: {
    padding: 16,
    borderRadius: 12,
    marginBottom: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 6,
    elevation: 3,
  },
  vendorHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  vendorName: {
    fontSize: 16,
    fontWeight: '600',
  },
  vendorResult: {
    fontSize: 14,
    marginBottom: 4,
  },
  vendorCategory: {
    fontSize: 12,
    fontStyle: 'italic',
  },
  statusDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
  },
  pieChartContainer: {
    alignItems: 'center',
    marginBottom: 30,
  },
  pieChartLabel: {
    marginTop: 10,
    fontSize: 16,
    fontWeight: '600',
  },
});

export default HomeScreen;
