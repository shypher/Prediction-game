import { useState } from "react";
import Alert from "./componets/Alert";
import ListGroup from "./componets/ListGroup";
import Button from "./componets/button";
import { Greet } from "./componets/Greet";
import { User } from "./componets/User";
import { UserList } from "./componets/UserList";
import { Status } from "./componets/Status";
import { Heading } from "./componets/heading";
import { Input } from "./componets/input";
import { Container } from "./componets/container";
function App() {

  return (
    <div className="App">
      <Container styles={{border:'1px solid black', padding:'1rem'}}/>
    </div>
  );
}
export default App;
