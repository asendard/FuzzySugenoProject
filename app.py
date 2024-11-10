import streamlit as st

# Fungsi Keanggotaan Segitiga
def triangular_membership(x, a, b, c):
    if x <= a or x >= c:
        return 0
    elif a < x < b:
        return (x - a) / (b - a)
    elif b <= x < c:
        return (c - x) / (c - b)
    else:
        return 0

# Fungsi Fuzzification
def fuzzification(request_count, security_level, anomalous_volume):
    # Request Count
    rc_low = triangular_membership(request_count, 0, 0, 500)
    rc_med = triangular_membership(request_count, 250, 500, 750)
    rc_high = triangular_membership(request_count, 500, 1000, 1000)
    
    # System Security Level
    sl_low = triangular_membership(security_level, 0, 0, 5)
    sl_med = triangular_membership(security_level, 2, 5, 8)
    sl_high = triangular_membership(security_level, 5, 10, 10)
    
    # Anomalous Data Volume
    av_low = triangular_membership(anomalous_volume, 0, 0, 250)
    av_med = triangular_membership(anomalous_volume, 100, 250, 400)
    av_high = triangular_membership(anomalous_volume, 250, 500, 500)
    
    return {
        "rc_low": rc_low, "rc_med": rc_med, "rc_high": rc_high,
        "sl_low": sl_low, "sl_med": sl_med, "sl_high": sl_high,
        "av_low": av_low, "av_med": av_med, "av_high": av_high
    }

# Fungsi Evaluasi Aturan Fuzzy (Sugeno)
def evaluate_rules(fuzzy_values):
    rules = []
    
    # Aturan-aturan Fuzzy Sugeno
    # Rule 1: Jika Request Count rendah, System Security Level rendah, Anomalous Data Volume rendah, maka Cyber Attack Risk Level = 30
    rules.append(min(fuzzy_values["rc_low"], fuzzy_values["sl_low"], fuzzy_values["av_low"]) * 30)
    
    # Rule 2: Jika Request Count sedang, System Security Level rendah, Anomalous Data Volume sedang, maka Cyber Attack Risk Level = 60
    rules.append(min(fuzzy_values["rc_med"], fuzzy_values["sl_low"], fuzzy_values["av_med"]) * 60)
    
    # Rule 3: Jika Request Count rendah, System Security Level tinggi, Anomalous Data Volume rendah, maka Cyber Attack Risk Level = 20
    rules.append(min(fuzzy_values["rc_low"], fuzzy_values["sl_high"], fuzzy_values["av_low"]) * 20)
    
    # Rule 4: Jika Request Count tinggi, System Security Level rendah, Anomalous Data Volume tinggi, maka Cyber Attack Risk Level = 95
    rules.append(min(fuzzy_values["rc_high"], fuzzy_values["sl_low"], fuzzy_values["av_high"]) * 95)
    
    # Rule 5: Jika Request Count sedang, System Security Level sedang, Anomalous Data Volume rendah, maka Cyber Attack Risk Level = 40
    rules.append(min(fuzzy_values["rc_med"], fuzzy_values["sl_med"], fuzzy_values["av_low"]) * 40)
    
    # Rule 6: Jika Request Count tinggi, System Security Level rendah, Anomalous Data Volume tinggi, maka Cyber Attack Risk Level = 85
    rules.append(min(fuzzy_values["rc_high"], fuzzy_values["sl_low"], fuzzy_values["av_high"]) * 85)
    
    # Rule 7: Jika Request Count rendah, System Security Level tinggi, Anomalous Data Volume rendah, maka Cyber Attack Risk Level = 10
    rules.append(min(fuzzy_values["rc_low"], fuzzy_values["sl_high"], fuzzy_values["av_low"]) * 10)
    
    # Rule 8: Jika Request Count sedang, System Security Level tinggi, Anomalous Data Volume rendah, maka Cyber Attack Risk Level = 50
    rules.append(min(fuzzy_values["rc_med"], fuzzy_values["sl_high"], fuzzy_values["av_low"]) * 50)
    
    # Rule 9: Jika Request Count tinggi, System Security Level sedang, Anomalous Data Volume tinggi, maka Cyber Attack Risk Level = 90
    rules.append(min(fuzzy_values["rc_high"], fuzzy_values["sl_med"], fuzzy_values["av_high"]) * 90)
    
    # Rule 10: Jika Request Count sedang, System Security Level sedang, Anomalous Data Volume rendah, maka Cyber Attack Risk Level = 35
    rules.append(min(fuzzy_values["rc_med"], fuzzy_values["sl_med"], fuzzy_values["av_low"]) * 35)
    
    return rules

# Fungsi Agregasi dan Defuzzifikasi (Rata-Rata Berbobot)
def defuzzification(rules):
    total_weighted_value = sum(rules)
    total_membership = sum([rule / (rule if rule != 0 else 1) for rule in rules])  # Handle division by zero
    if total_membership == 0:
        return 0  # Avoid division by zero
    return total_weighted_value / total_membership

# Fungsi Utama untuk FIS
def fis_system(request_count, security_level, anomalous_volume):
    # Step 1: Fuzzification
    fuzzy_values = fuzzification(request_count, security_level, anomalous_volume)
    
    # Step 2: Evaluate Rules
    rules = evaluate_rules(fuzzy_values)
    
    # Step 3: Defuzzification
    risk_level = defuzzification(rules)
    return risk_level

# GUI menggunakan Streamlit
def main():
    st.title("Cyber Attack Risk Level Prediction")
    
    # Input dari pengguna
    request_count = st.slider("Request Count", 0, 1000, 200)
    security_level = st.slider("System Security Level", 0, 10, 5)
    anomalous_volume = st.slider("Anomalous Data Volume", 0, 500, 150)
    
    # Prediksi menggunakan FIS
    risk_level = fis_system(request_count, security_level, anomalous_volume)
    
    # Tampilkan hasil
    st.write("Cyber Attack Risk Level:", round(risk_level, 2))

if __name__ == "__main__":
    main()
