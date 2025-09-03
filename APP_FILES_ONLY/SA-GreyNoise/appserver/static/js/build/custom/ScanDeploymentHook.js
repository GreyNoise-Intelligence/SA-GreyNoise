class ScanDeploymentHook {
  constructor(globalConfig, serviceName, state, mode, util) {
    this.globalConfig = globalConfig;
    this.serviceName = serviceName;
    this.state = state;
    this.mode = mode;
    this.util = util;
}

  isTrue = (val) => {
    var value = String(val).trim().toUpperCase();
      if (value === "1" || value === "TRUE") {
        return true;
      }
    return false;
  };

  onRender(){
    this.util.setState((prevState) => {
        const newState = { data: { ...prevState.data } };
        if (this.isTrue(newState.data.update_risk_score_to_splunk_es.value)) {
            // display risk score fields
            newState.data.malicious_score.display = true;
            newState.data.suspicious_score.display = true;
            newState.data.benign_score.display = true;
            newState.data.unknown_score.display = true;
        } else {
            // hide risk score fields
            newState.data.malicious_score.display = false;
            newState.data.suspicious_score.display = false;
            newState.data.benign_score.display = false;
            newState.data.unknown_score.display = false;
        }
        return newState;
    });
  }

  onChange(field, value, dataDict){
    if (field === "update_risk_score_to_splunk_es") {
        if (this.isTrue(value)) {
            // display risk score fields
            this.util.setState((prevState) => {
                const newState = { data: { ...prevState.data } };
                newState.data.malicious_score.display = true;
                newState.data.suspicious_score.display = true;
                newState.data.benign_score.display = true;
                newState.data.unknown_score.display = true;
                return newState;
            });
        } else {
            // hide risk score fields
            this.util.setState((prevState) => {
                const newState = { data: { ...prevState.data } };
                newState.data.malicious_score.display = false;
                newState.data.suspicious_score.display = false;
                newState.data.benign_score.display = false;
                newState.data.unknown_score.display = false;
                return newState;
            });
        }
    }
  }
}

export default ScanDeploymentHook;