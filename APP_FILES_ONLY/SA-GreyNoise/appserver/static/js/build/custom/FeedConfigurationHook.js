class FeedConfigurationHook {
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
        if (this.isTrue(newState.data.ingest_feed_to_index.value)) {
            // display feed index fields
            newState.data.feed_index.display = true;
        } else {
            // hide feed index fields
            newState.data.feed_index.display = false;
        }
        return newState;
    });
  }

  onChange(field, value, dataDict){
    if (field === "ingest_feed_to_index") {
        if (this.isTrue(value)) {
            // display feed index fields
            this.util.setState((prevState) => {
                const newState = { data: { ...prevState.data } };
                newState.data.feed_index.display = true;
                return newState;
            });
        } else {
            // hide feed index fields
            this.util.setState((prevState) => {
                const newState = { data: { ...prevState.data } };
                newState.data.feed_index.display = false;
                return newState;
            });
        }
    }
  }
}

export default FeedConfigurationHook;