type UserListProp= {
    names:{
        first: string,
        last: string
    }[]
}



export const UserList = (props: UserListProp) => {
    return(
        <div>
           {props.names.map((names)=>{
            return(
                <h2 key={names.first}>
                    {names.first} {names.last}
                </h2>
            )
           })
           }
        </div>
    )
}