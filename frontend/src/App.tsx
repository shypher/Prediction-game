import { useState } from "react"
import Alert from "./componets/Alert"
import ListGroup from "./componets/ListGroup"
import Button from "./componets/button"
function App(){
  const [alertVisible, setAlertVisibility] = useState(false)
  return <div>
    {alertVisible&&<Alert onClose={()=> setAlertVisibility(false)}>Shimmeh Alert</Alert>}
    <Button onClick={()=>setAlertVisibility(true)}>Shimmeh</Button>
  </div>
}
export default App