export class WebAuthComponent implements OnInit{


  // -------------------- Constructor & Subscriptions --------------------
  constructor(public bioAuthService: BiometricAuthService){}




// -------------------- Lifecycle --------------------
  ngOnInit() {

  }

// -------------------- Action Function --------------------
  initWebAuthn() {
    this.bioAuthService.registerAuthentication().then(authStatus => {
      if (authStatus === 'success') {
	// action 1
      } else if (authStatus === 'otp') {
        // action 2
      } else {
        // action 3
      }
    });
  }



}