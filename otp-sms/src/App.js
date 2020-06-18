import React, { Component } from 'react';
import PhoneInput, { isValidPhoneNumber } from 'react-phone-number-input';
import 'react-phone-number-input/style.css';
import OtpInput from 'react-otp-input';

const OTP_LENGTH = 6;

export default class App extends Component {

  state = {};

  setPhone = (phone) => {
    this.setState({phone});
  }

  setOtp = (otp) => {
    this.setState({otp});
    if (otp.length === OTP_LENGTH) {
      if (otp === '111111') this.setState({screen: 'done'});
      else this.setState({screen: 'otperror'});
    }
  }

  resetState = () => {
    this.setState({screen: null, otp: null, phone: null});
  }

  codeScreen = () => {
    this.setState({otp: null, screen: 'code'});
  }

  sendOTP = () => {
    this.codeScreen();
  }

  render() {
    const { screen, otp, phone } = this.state;

    if (screen === 'code') return (
      <div style={{width: 300}}>
        Enter in your {OTP_LENGTH} digit code:
        <br />
        <OtpInput
          shouldAutoFocus={true}
          onChange={this.setOtp}
          numInputs={OTP_LENGTH}
          value={otp}
          separator={<span>-</span>}
        />
      </div>
    );

    if (screen === 'otperror') return (
      <div>
        Error: Incorrect code.
        <br />
        Phone: {phone}
        <br />
        <button onClick={this.resetState}>Re-enter phone number</button>
        <br />
        <button onClick={this.codeScreen}>Re-enter code</button>
        <br />
        <button onClick={this.sendOTP}>Re-send OTP</button>
      </div>
    );

    if (screen === 'done') return (
        <div>OTP Complete! (TODO: automatic redirect)</div>
    );

    return (
      <div style={{width: 300}}>
        <PhoneInput
          placeholder="Enter phone number"
          defaultCountry="US"
          value={phone}
          onChange={this.setPhone} />
        <br />
        <button disabled={!isValidPhoneNumber(phone)} onClick={this.sendOTP}>Send Code</button>
      </div>
    );
  }
  
}
