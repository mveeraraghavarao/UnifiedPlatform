import {HTTP_INTERCEPTORS} from "@angular/common/http";
import {ErrorInterceptor} from "./error-interceptor";
import {HttpTokenInterceptor} from "./http-token-interceptor";

/** Http interceptor providers in outside-in order */
export const HttpInterceptorProviders = [
  {
    provide: HTTP_INTERCEPTORS,
    useClass: ErrorInterceptor,
    multi: true,
  },
  {
    provide: HTTP_INTERCEPTORS,
    useClass: HttpTokenInterceptor,
    multi: true,
  },
];