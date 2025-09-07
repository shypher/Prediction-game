type userProps = {
    name:{
        first:string,
        last: string
        }
}


export const User = (props:userProps) =>{
    return <div>{props.name.first} {props.name.last}</div>
}