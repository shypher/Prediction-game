type GreetProps = {
  userName: string;
  messagesCount?: number;
  isLoggedIn: boolean;
};

export const Greet = (props: GreetProps) => {
    const { messagesCount = 0 } = props
    return (
    <div>
      <h2>
        {props.isLoggedIn
          ? `Welcome ${props.userName}! You have ${messagesCount} unread messages`
          : 'Welcome Guest'}
      </h2>
    </div>
  );
};
