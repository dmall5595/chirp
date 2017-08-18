import { NgModule } from "@angular/core";
import { BrowserModule } from "@angular/platform-browser";
import { FormsModule } from "@angular/forms";

import { AppComponent } from "./app.component";

import "../../scss/styles.scss";

@NgModule({
    imports: [ BrowserModule, FormsModule ],
    declarations: [ AppComponent ],
    bootstrap: [ AppComponent ],
})
export class AppModule { }
